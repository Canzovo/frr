// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra neighbor table management
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 */

#include <zebra.h>

#include "command.h"
#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/interface.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_neigh.h"
#include "zebra/kernel_netlink.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_vxlan.h"
#include <linux/neighbour.h>
#include "zebra/zapi_msg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_INFO, "Zebra neigh table");
DEFINE_MTYPE_STATIC(ZEBRA, ZNEIGH_ENT, "Zebra neigh entry");

static int zebra_neigh_rb_cmp(const struct zebra_neigh_ent *n1,
			      const struct zebra_neigh_ent *n2)
{
	if (n1->ifindex < n2->ifindex)
		return -1;

	if (n1->ifindex > n2->ifindex)
		return 1;

	if (n1->ip.ipa_type < n2->ip.ipa_type)
		return -1;

	if (n1->ip.ipa_type > n2->ip.ipa_type)
		return 1;

	if (n1->ip.ipa_type == AF_INET) {
		if (n1->ip.ipaddr_v4.s_addr < n2->ip.ipaddr_v4.s_addr)
			return -1;

		if (n1->ip.ipaddr_v4.s_addr > n2->ip.ipaddr_v4.s_addr)
			return 1;

		return 0;
	}

	return memcmp(&n1->ip.ipaddr_v6, &n2->ip.ipaddr_v6, IPV6_MAX_BYTELEN);
}

RB_GENERATE(zebra_neigh_rb_head, zebra_neigh_ent, rb_node, zebra_neigh_rb_cmp);

static struct zebra_neigh_ent *zebra_neigh_find(ifindex_t ifindex,
						struct ipaddr *ip)
{
	struct zebra_neigh_ent tmp;

	tmp.ifindex = ifindex;
	memcpy(&tmp.ip, ip, sizeof(*ip));
	return RB_FIND(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, &tmp);
}

static struct zebra_neigh_ent *
zebra_neigh_new(ifindex_t ifindex, struct ipaddr *ip, struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	n = XCALLOC(MTYPE_ZNEIGH_ENT, sizeof(struct zebra_neigh_ent));

	memcpy(&n->ip, ip, sizeof(*ip));
	n->ifindex = ifindex;
	if (mac) {
		memcpy(&n->mac, mac, sizeof(*mac));
		SET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);
	}

	/* Add to rb_tree */
	if (RB_INSERT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n)) {
		XFREE(MTYPE_ZNEIGH_ENT, n);
		return NULL;
	}

	/* Initialise the pbr rule list */
	n->pbr_rule_list = list_new();
	listset_app_node_mem(n->pbr_rule_list);

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh new if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	return n;
}

static void zebra_neigh_pbr_rules_update(struct zebra_neigh_ent *n)
{
	struct zebra_pbr_rule *rule;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(n->pbr_rule_list, node, rule))
		dplane_pbr_rule_update(rule, rule);
}

static void zebra_neigh_free(struct zebra_neigh_ent *n)
{
	if (listcount(n->pbr_rule_list)) {
		/* if rules are still using the neigh mark it as inactive and
		 * update the dataplane
		 */
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);
		memset(&n->mac, 0, sizeof(n->mac));
		zebra_neigh_pbr_rules_update(n);
		return;
	}
	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh free if %d %pIA %pEA", n->ifindex,
			   &n->ip, &n->mac);

	/* cleanup resources maintained against the neigh */
	list_delete(&n->pbr_rule_list);

	RB_REMOVE(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, n);

	XFREE(MTYPE_ZNEIGH_ENT, n);
}

/* kernel neigh del */
void zebra_neigh_del(struct interface *ifp, struct ipaddr *ip)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh del if %s/%d %pIA", ifp->name,
			   ifp->ifindex, ip);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (!n)
		return;
	zebra_neigh_free(n);
}

/* kernel neigh delete all for a given interface */
void zebra_neigh_del_all(struct interface *ifp)
{
	struct zebra_neigh_ent *n, *next;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh delete all for interface %s/%d",
			   ifp->name, ifp->ifindex);

	RB_FOREACH_SAFE (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree, next) {
		if (n->ifindex == ifp->ifindex) {
			/* Free the neighbor directly instead of looking it up again */
			zebra_neigh_free(n);
		}
	}
}

/* kernel neigh add */
void zebra_neigh_add(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh add if %s/%d %pIA %pEA", ifp->name,
			   ifp->ifindex, ip, mac);

	n = zebra_neigh_find(ifp->ifindex, ip);
	if (n) {
		if (!memcmp(&n->mac, mac, sizeof(*mac)))
			return;

		memcpy(&n->mac, mac, sizeof(*mac));
		SET_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE);

		/* update rules linked to the neigh */
		zebra_neigh_pbr_rules_update(n);
	} else {
		zebra_neigh_new(ifp->ifindex, ip, mac);
	}
}

void zebra_neigh_deref(struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n = rule->action.neigh;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh deref if %d %pIA by pbr rule %u",
			   n->ifindex, &n->ip, rule->rule.seq);

	rule->action.neigh = NULL;
	/* remove rule from the list and free if it is inactive */
	list_delete_node(n->pbr_rule_list, &rule->action.neigh_listnode);
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ENT_ACTIVE))
		zebra_neigh_free(n);
}

/* XXX - this needs to work with evpn's neigh read */
static void zebra_neigh_read_on_first_ref(void)
{
	static bool neigh_read_done;

	if (!neigh_read_done) {
		neigh_read(zebra_ns_lookup(NS_DEFAULT));
		neigh_read_done = true;
	}
}

void zebra_neigh_ref(int ifindex, struct ipaddr *ip,
		     struct zebra_pbr_rule *rule)
{
	struct zebra_neigh_ent *n;

	if (IS_ZEBRA_DEBUG_NEIGH)
		zlog_debug("zebra neigh ref if %d %pIA by pbr rule %u", ifindex,
			   ip, rule->rule.seq);

	zebra_neigh_read_on_first_ref();
	n = zebra_neigh_find(ifindex, ip);
	if (!n)
		n = zebra_neigh_new(ifindex, ip, NULL);

	/* link the pbr entry to the neigh */
	if (rule->action.neigh == n)
		return;

	if (rule->action.neigh)
		zebra_neigh_deref(rule);

	rule->action.neigh = n;
	listnode_init(&rule->action.neigh_listnode, rule);
	listnode_add(n->pbr_rule_list, &rule->action.neigh_listnode);
}

static void zebra_neigh_show_one(struct vty *vty, struct zebra_neigh_ent *n)
{
	char mac_buf[ETHER_ADDR_STRLEN];
	char ip_buf[INET6_ADDRSTRLEN];
	struct interface *ifp;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					n->ifindex);
	ipaddr2str(&n->ip, ip_buf, sizeof(ip_buf));
	prefix_mac2str(&n->mac, mac_buf, sizeof(mac_buf));
	vty_out(vty, "%-20s %-30s %-18s %u\n", ifp ? ifp->name : "-", ip_buf,
		mac_buf, listcount(n->pbr_rule_list));
}

void zebra_neigh_show(struct vty *vty)
{
	struct zebra_neigh_ent *n;

	vty_out(vty, "%-20s %-30s %-18s %s\n", "Interface", "Neighbor", "MAC",
		"#Rules");
	RB_FOREACH (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree)
		zebra_neigh_show_one(vty, n);
}

void zebra_neigh_init(void)
{
	zneigh_info = XCALLOC(MTYPE_ZNEIGH_INFO, sizeof(*zrouter.neigh_info));
	RB_INIT(zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree);
}

void zebra_neigh_terminate(void)
{
	struct zebra_neigh_ent *n, *next;

	if (!zrouter.neigh_info)
		return;

	RB_FOREACH_SAFE (n, zebra_neigh_rb_head, &zneigh_info->neigh_rb_tree,
			 next)
		zebra_neigh_free(n);
	XFREE(MTYPE_ZNEIGH_INFO, zneigh_info);
}


void zebra_neigh_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	switch (op)
	{
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_DISCOVER:
		/*do what should refactor the netlink_ipneigh_change function*/
		zebra_neigh_ipaddr_update(ctx);
		break;
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_DELETE:
		/*do what should refactor the netlink_macfdb_change function*/
		zebra_neigh_macfdb_update(ctx);
		break;
	default:
		/* other dplane ops not handled here */
		break;
	}
	
	return;
}

void zebra_neigh_ipaddr_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	struct ipaddr ip = dplane_ctx_get_neigh_ipaddr(ctx);
	ns_id_t ns_id = dplane_ctx_get_ns_id(ctx);
	int32_t ndm_ifindex = dplane_ctx_get_ifindex(ctx);

	struct interface *ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm_ifindex);
	/* The interface should exist. */
	if (!ifp || !ifp->info)
		return;

	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	uint16_t ndm_state = dplane_ctx_get_neigh_ndm_state(ctx);
	uint32_t ndm_family = dplane_ctx_get_neigh_ndm_family(ctx);

	/* if kernel deletes our rfc5549 neighbor entry, re-install it */
	if(op == DPLANE_OP_NEIGH_IP_DELETE && (ndm_state & NUD_PERMANENT)) {
		netlink_handle_5549(ndm_family, ndm_state, zif, ifp, &ip, false);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry eceived is a 5549 entry, finished");
		return;
	}

	/* if kernel marks our rfc5549 neighbor entry invalid, re-install it */
	if (op == DPLANE_OP_NEIGH_IP_INSTALL && !(ndm_state & NUD_VALID))
		netlink_handle_5549(ndm_family, ndm_state, zif, ifp, &ip, true);

	int l2_len = dplane_ctx_get_neigh_l2_len(ctx);
	
	const char *desc = dplane_ctx_get_neigh_desc(ctx);
	union sockunion link_layer_ipv4;

	if (l2_len) {
		sockunion_family(&link_layer_ipv4) = AF_INET;
		memcpy((void *)sockunion_get_addr(&link_layer_ipv4), desc, l2_len);
	} else
		sockunion_family(&link_layer_ipv4) = AF_UNSPEC;

	int cmd = dplane_ctx_get_neigh_cmd(ctx);

	zsend_neighbor_notify(cmd, ifp, &ip,
				// netlink_nbr_entry_state_to_zclient(ndm_state),
				ndm_state, &link_layer_ipv4, l2_len);
	
	if(op == DPLANE_OP_NEIGH_DISCOVER)
		return;

	struct interface *link_if;
	if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
						    zif->link_ifindex);
		if (!link_if)
			return;
	} else if (IS_ZEBRA_IF_BRIDGE(ifp))
		link_if = ifp;
	else {
		link_if = NULL;
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry received is not on a VLAN or a BRIDGE, ignoring");
	}

	if (op == DPLANE_OP_NEIGH_IP_INSTALL) {

		struct ethaddr mac = dplane_ctx_get_neigh_mac(ctx);
		bool is_ext = dplane_ctx_get_neigh_is_ext(ctx);
		bool is_router = dplane_ctx_get_neigh_is_router(ctx);
		bool local_inactive = dplane_ctx_get_neigh_local_inactive(ctx);
		bool dp_static = dplane_ctx_get_neigh_dp_static(ctx);
		int mac_present = dplane_ctx_get_neigh_mac_present(ctx);
		uint32_t ext_flags = dplane_ctx_get_neigh_ext_flags(ctx);
		uint16_t nlmsg_type = dplane_ctx_get_neigh_nlmsg_type(ctx);
		uint32_t ndm_flags = dplane_ctx_get_neigh_ndm_flags(ctx);

		char buf[ETHER_ADDR_STRLEN];

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"Rx %s family %s IF %s(%u) vrf %s(%u) IP %pIA MAC %s state 0x%x flags 0x%x ext_flags 0x%x",
				nl_msg_type_to_str(nlmsg_type),
				nl_family_to_str(ndm_family), ifp->name,
				ndm_ifindex, ifp->vrf->name,
				ifp->vrf->vrf_id, &ip,
				mac_present
					? prefix_mac2str(&mac, buf, sizeof(buf))
					: "",
				ndm_state, ndm_flags, ext_flags);

		if (ndm_state & NUD_VALID) {
			if (is_ext)
				zebra_neigh_del(ifp, &ip);
			else	
				zebra_neigh_add(ifp, &ip, &mac);

			if (link_if)
				zebra_vxlan_handle_kernel_neigh_update(
					ifp, link_if, &ip, &mac, ndm_state,
					is_ext, is_router, local_inactive,
					dp_static);
			return;
		}

		zebra_neigh_del(ifp, &ip);
		if (link_if)
			zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
		return;
	}

	zebra_neigh_del(ifp, &ip);
	if (link_if)
		zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);

	return;
}

void zebra_neigh_macfdb_update(struct zebra_dplane_ctx *ctx)
{
	ns_id_t ns_id = dplane_ctx_get_ns_id(ctx);
	ifindex_t ndm_ifindex = dplane_ctx_get_ifindex(ctx);
	struct interface *ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), ndm_ifindex);
	bool vni_mcast_grp = false;

	if (!ifp || !ifp->info)
		return;
	
	/* The interface should be something we're interested in. */
	if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
		return;

	struct interface *br_if;
	struct zebra_if *zif = (struct zebra_if *)ifp->info;
	uint16_t nlmsg_type = dplane_ctx_get_fdb_nlmsg_type(ctx);

	if ((br_if = zif->brslave_info.br_if) == NULL) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s AF_BRIDGE IF %s(%u) brIF %u - no bridge master",
				nl_msg_type_to_str(nlmsg_type), ifp->name, ndm_ifindex,
				zif->brslave_info.bridge_ifindex);
		return;
	}

	enum dplane_op_e op = dplane_ctx_get_op(ctx);
	ifindex_t vni = dplane_ctx_get_fdb_vni(ctx);

	/* For per vni device, vni comes from device itself */
	if (IS_ZEBRA_IF_VXLAN(ifp) && IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		struct zebra_vxlan_vni *vnip;

		vnip = zebra_vxlan_if_vni_find(zif, 0);
		vni = vnip->vni;
	}
	
	struct ethaddr mac = dplane_ctx_get_neigh_mac(ctx);
	struct in_addr vtep_ip = dplane_ctx_get_fdb_vtep_ip(ctx);
	vni_mcast_grp = is_mac_vni_mcast_group(&mac, vni, vtep_ip);
	
	bool sticky = dplane_ctx_get_fdb_is_sticky(ctx);
	bool local_inactive = dplane_ctx_get_fdb_local_inactive(ctx);
	bool dp_static = dplane_ctx_get_fdb_dp_static(ctx);
	uint32_t vid = dplane_ctx_get_fdb_vid(ctx);
	uint32_t nhg_id = dplane_ctx_get_fdb_nhg_id(ctx);
	int dst_present = dplane_ctx_get_fdb_dst_present(ctx);
	uint16_t ndm_state = dplane_ctx_get_fdb_ndm_state(ctx);
	uint8_t ndm_flags = dplane_ctx_get_fdb_ndm_flags(ctx);

	if(op == DPLANE_OP_NEIGH_INSTALL) {
		/* Drop "permanent" entries. */
		if (!vni_mcast_grp && (ndm_state & NUD_PERMANENT)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"        Dropping entry because of NUD_PERMANENT");
			return;
		}

		if (IS_ZEBRA_IF_VXLAN(ifp)) {
			if (!dst_present)
				return;

			if (vni_mcast_grp) {
				zebra_vxlan_if_vni_mcast_group_add_update(ifp, vni, &vtep_ip);
				return;
			}
				
			zebra_vxlan_dp_network_mac_add(
				ifp, br_if, &mac, vid, vni, nhg_id, sticky,
				!!(ndm_flags & NTF_EXT_LEARNED));
			return;
		}

		zebra_vxlan_local_mac_add_update(ifp, br_if, &mac, vid,
				sticky, local_inactive, dp_static);
		return;
	}

	/* This is a delete notification.
	 * Ignore the notification with IP dest as it may just signify that the
	 * MAC has moved from remote to local. The exception is the special
	 * all-zeros MAC that represents the BUM flooding entry; we may have
	 * to readd it. Otherwise,
	 *  1. For a MAC over VxLan, check if it needs to be refreshed(readded)
	 *  2. For a MAC over "local" interface, delete the mac
	 * Note: We will get notifications from both bridge driver and VxLAN
	 * driver.
	 */

	if (dst_present) {
		if (vni_mcast_grp) {
			zebra_vxlan_if_vni_mcast_group_del(ifp, vni, &vtep_ip);
			return;
		}
			
		if (is_zero_mac(&mac) && vni) {
			zebra_vxlan_check_readd_vtep(ifp, vni, vtep_ip);
			return;
		}
		return;
	}

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return;

	zebra_vxlan_local_mac_del(ifp, br_if, &mac, vid);
	return;
}
