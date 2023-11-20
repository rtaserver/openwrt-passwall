#!/bin/bash

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/nftables.sh
NFTSET_LANLIST="passwall_lanlist"
NFTSET_VPSLIST="passwall_vpslist"
NFTSET_SHUNTLIST="passwall_shuntlist"
NFTSET_GFW="passwall_gfwlist"
NFTSET_CHN="passwall_chnroute"
NFTSET_BLACKLIST="passwall_blacklist"
NFTSET_WHITELIST="passwall_whitelist"
NFTSET_BLOCKLIST="passwall_blocklist"

NFTSET_LANLIST6="passwall_lanlist6"
NFTSET_VPSLIST6="passwall_vpslist6"
NFTSET_SHUNTLIST6="passwall_shuntlist6"
NFTSET_GFW6="passwall_gfwlist6"
NFTSET_CHN6="passwall_chnroute6"
NFTSET_BLACKLIST6="passwall_blacklist6"
NFTSET_WHITELIST6="passwall_whitelist6"
NFTSET_BLOCKLIST6="passwall_blocklist6"

FORCE_INDEX=0

. /lib/functions/network.sh

FWI=$(uci -q get firewall.passwall.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	# acl mac address
	elif [ -n "$(echo $1 | grep -E '([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}')" ]; then
		echo "$2 {$1}"
	else
		echo "$2 {$(echo $1 | sed 's/:/-/g')}"
	fi
}

insert_rule_before() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

insert_rule_after() {
	[ $# -ge 4 ] || {
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		nft "add rule $table_name $chain_name $rule"
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		nft "insert rule $table_name $chain_name position $_index $rule"
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		echolog "Incorrect index enumeration method (nftables), terminate execution!"
		return 1
	}
	local table_name="${1}"; shift
	local chain_name="${1}"; shift
	local keyword="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$(nft -a list chain $table_name $chain_name 2>/dev/null | grep "$keyword" | awk -F '# handle ' '{print$2}' | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="counter redirect"
	[ -n "$1" ] && {
		local s="$s to :$1"
		[ "$2" == "MARK" ] && s="counter meta mark set $1"
		[ "$2" == "TPROXY" ] && {
			s="counter meta mark 1 tproxy to :$1"
		}
		[ "$2" == "TPROXY4" ] && {
			s="counter meta mark 1 tproxy ip to :$1"
		}
		[ "$2" == "TPROXY6" ] && {
			s="counter meta mark 1 tproxy ip6 to :$1"
		}

	}
	echo $s
}

destroy_nftset() {
	for i in "$@"; do
		nft flush set inet fw4 $i 2>/dev/null
		nft delete set inet fw4 $i 2>/dev/null
	done
}

insert_nftset() {
	local nftset_name="${1}"; shift
	local timeout_argument="${1}"; shift
	local defalut_timeout_argument="3650d"
	local nftset_elements

	[ -n "${1}" ] && {
		if [ "$timeout_argument" == "0" ]; then
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $defalut_timeout_argument, /g" | sed "s/$/ timeout $defalut_timeout_argument/")
		else
			nftset_elements=$(echo -e $@ | sed "s/\s/ timeout $timeout_argument, /g" | sed "s/$/ timeout $timeout_argument/")
		fi
		mkdir -p $TMP_PATH2/nftset
		cat > "$TMP_PATH2/nftset/$nftset_name" <<-EOF
			define $nftset_name = {$nftset_elements}	
			add element inet fw4 $nftset_name \$$nftset_name
		EOF
		nft -f "$TMP_PATH2/nftset/$nftset_name"
		rm -rf "$TMP_PATH2/nftset"
	}
}

gen_nftset() {
	local nftset_name="${1}"; shift
	local ip_type="${1}"; shift
	#  0 - don't set defalut timeout
	local timeout_argument_set="${1}"; shift
	#  0 - don't let element timeout(3650 days)
	local timeout_argument_element="${1}"; shift

	nft "list set inet fw4 $nftset_name" &>/dev/null
	if [ $? -ne 0 ]; then
		if [ "$timeout_argument_set" == "0" ]; then
			nft "add set inet fw4 $nftset_name { type $ip_type; flags interval, timeout; auto-merge; }"
		else
			nft "add set inet fw4 $nftset_name { type $ip_type; flags interval, timeout; timeout $timeout_argument_set; gc-interval $timeout_argument_set; auto-merge; }"
		fi
	fi
	[ -n "${1}" ] && insert_nftset $nftset_name $timeout_argument_element $@
}

get_redirect_ipv4() {
	case "$1" in
	disable)
		echo "counter return"
		;;
	global)
		echo "$(REDIRECT $2 $3)"
		;;
	gfwlist)
		echo "ip daddr @$NFTSET_GFW $(REDIRECT $2 $3)"
		;;
	chnroute)
		echo "ip daddr != @$NFTSET_CHN $(REDIRECT $2 $3)"
		;;
	returnhome)
		echo "ip daddr @$NFTSET_CHN $(REDIRECT $2 $3)"
		;;
	esac
}

get_redirect_ipv6() {
	case "$1" in
	disable)
		echo "counter return"
		;;
	global)
		echo "$(REDIRECT $2 $3)"
		;;
	gfwlist)
		echo "ip6 daddr @$NFTSET_GFW6 $(REDIRECT $2 $3)"
		;;
	chnroute)
		echo "ip6 daddr != @$NFTSET_CHN6 $(REDIRECT $2 $3)"
		;;
	returnhome)
		echo "ip6 daddr @$NFTSET_CHN6 $(REDIRECT $2 $3)"
		;;
	esac
}

get_nftset_ipv4() {
	case "$1" in
	gfwlist)
		echo "ip daddr @$NFTSET_GFW counter"
		;;
	chnroute)
		echo "ip daddr != @$NFTSET_CHN counter"
		;;
	returnhome)
		echo "$ip daddr @$NFTSET_CHN counter"
		;;
	esac
}

get_nftset_ipv6() {
	case "$1" in
	gfwlist)
		echo "ip6 daddr @$NFTSET_GFW6 counter"
		;;
	chnroute)
		echo "ip6 daddr != @$NFTSET_CHN6 counter"
		;;
	returnhome)
		echo "$ip6 daddr @$NFTSET_CHN6 counter"
		;;
	esac
}

get_action_chain_name() {
	case "$1" in
	disable)
		echo "No proxy"
		;;
	global)
		echo "Global proxy"
		;;
	gfwlist)
		echo "Firewall list"
		;;
	chnroute)
		echo "Outside China list"
		;;
	returnhome)
		echo "China list"
		;;
	direct/proxy)
		echo "Only use direct/proxy list"
		;;
	esac
}

gen_lanlist() {
	cat $RULES_PATH/lanlist_ipv4 | tr -s '\n' | grep -v "^#"
}

gen_lanlist_6() {
	cat $RULES_PATH/lanlist_ipv6 | tr -s '\n' | grep -v "^#"
}

get_wan_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan NET_IF
	network_get_ipaddr NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

get_wan6_ip() {
	local NET_IF
	local NET_ADDR
	
	network_flush_cache
	network_find_wan6 NET_IF
	network_get_ipaddr6 NET_ADDR "${NET_IF}"
	
	echo $NET_ADDR
}

load_acl() {
	[ "$ENABLED_ACLS" == 1 ] && {
		acl_app
		echolog "Access control:"
		for sid in $(ls -F ${TMP_ACL_PATH} | grep '/$' | awk -F '/' '{print $1}'); do
			eval $(uci -q show "${CONFIG}.${sid}" | cut -d'.' -sf 3-)
			
			tcp_proxy_mode=${tcp_proxy_mode:-default}
			udp_proxy_mode=${udp_proxy_mode:-default}
			tcp_no_redir_ports=${tcp_no_redir_ports:-default}
			udp_no_redir_ports=${udp_no_redir_ports:-default}
			tcp_proxy_drop_ports=${tcp_proxy_drop_ports:-default}
			udp_proxy_drop_ports=${udp_proxy_drop_ports:-default}
			tcp_redir_ports=${tcp_redir_ports:-default}
			udp_redir_ports=${udp_redir_ports:-default}
			tcp_node=${tcp_node:-default}
			udp_node=${udp_node:-default}
			[ "$tcp_proxy_mode" = "default" ] && tcp_proxy_mode=$TCP_PROXY_MODE
			[ "$udp_proxy_mode" = "default" ] && udp_proxy_mode=$UDP_PROXY_MODE
			[ "$tcp_no_redir_ports" = "default" ] && tcp_no_redir_ports=$TCP_NO_REDIR_PORTS
			[ "$udp_no_redir_ports" = "default" ] && udp_no_redir_ports=$UDP_NO_REDIR_PORTS
			[ "$tcp_proxy_drop_ports" = "default" ] && tcp_proxy_drop_ports=$TCP_PROXY_DROP_PORTS
			[ "$udp_proxy_drop_ports" = "default" ] && udp_proxy_drop_ports=$UDP_PROXY_DROP_PORTS
			[ "$tcp_redir_ports" = "default" ] && tcp_redir_ports=$TCP_REDIR_PORTS
			[ "$udp_redir_ports" = "default" ] && udp_redir_ports=$UDP_REDIR_PORTS
			[ "$tcp_no_redir_ports" = "1:65535" ] && tcp_proxy_mode="disable"
			[ "$udp_no_redir_ports" = "1:65535" ] && udp_proxy_mode="disable"

			tcp_node_remark=$(config_n_get $TCP_NODE remarks)
			udp_node_remark=$(config_n_get $UDP_NODE remarks)
			[ -s "${TMP_ACL_PATH}/${sid}/var_tcp_node" ] && tcp_node=$(cat ${TMP_ACL_PATH}/${sid}/var_tcp_node)
			[ -s "${TMP_ACL_PATH}/${sid}/var_udp_node" ] && udp_node=$(cat ${TMP_ACL_PATH}/${sid}/var_udp_node)
			[ -s "${TMP_ACL_PATH}/${sid}/var_tcp_port" ] && tcp_port=$(cat ${TMP_ACL_PATH}/${sid}/var_tcp_port)
			[ -s "${TMP_ACL_PATH}/${sid}/var_udp_port" ] && udp_port=$(cat ${TMP_ACL_PATH}/${sid}/var_udp_port)
			
			[ "$udp_node" == "default" ] && [ "$UDP_NODE" = "nil" ] && [ "$TCP_UDP" = "1" ] && udp_node=$TCP_NODE
			[ -n "$tcp_node" ] && [ "$tcp_node" != "default" ] && tcp_node_remark=$(config_n_get $tcp_node remarks)
			[ -n "$udp_node" ] && [ "$udp_node" != "default" ] && udp_node_remark=$(config_n_get $udp_node remarks)
			
			for i in $(cat ${TMP_ACL_PATH}/${sid}/rule_list); do
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "ip saddr")
					msg="Remarksã€$remarksã€‘ï¼ŒIP rangeã€${_iprange}ã€‘,"
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					_ipt_source="ip daddr @${_ipset}"
					msg="Remarksã€$remarksã€‘ï¼ŒNFTsetã€${_ipset}ã€‘,"
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "ip saddr")
					msg="Remarksã€$remarksã€‘ï¼ŒIPã€${_ip}ã€‘,"
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "ether saddr")
					msg="Remarksã€$remarksã€‘ï¼ŒMACã€${_mac}ã€‘,"
				else
					continue
				fi

				[ -n "$tcp_port" ] && {
					if [ "$tcp_proxy_mode" != "disable" ]; then
						[ -s "${TMP_ACL_PATH}/${sid}/var_redirect_dns_port" ] && nft "add rule inet fw4 PSW_REDIRECT ip protocol udp ${_ipt_source} udp dport 53 counter redirect to $(cat ${TMP_ACL_PATH}/${sid}/var_redirect_dns_port) comment \"$remarks\""
						msg2="${msg}Use TCP node [$tcp_node_remark] [$(get_action_chain_name $tcp_proxy_mode)]"
						if [ -n "${is_tproxy}" ]; then
							msg2="${msg2}(TPROXY:${tcp_port})proxy"
						else
							msg2="${msg2}(REDIRECT:${tcp_port})proxy"
						fi
						
						[ "$accept_icmp" = "1" ] && {
							nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT) comment \"$remarks\""
							nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_SHUNTLIST $(REDIRECT) comment \"$remarks\""
							nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} ip daddr @$NFTSET_BLACKLIST $(REDIRECT) comment \"$remarks\""
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} $(get_redirect_ipv4 $tcp_proxy_mode) comment \"$remarks\""
							nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ${_ipt_source} return comment \"$remarks\""
						}

						[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
							nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_SHUNTLIST6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} ip6 daddr @$NFTSET_BLACKLIST6 $(REDIRECT) comment \"$remarks\"" 2>/dev/null
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} $(get_redirect_ipv6 $tcp_proxy_mode) comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ${_ipt_source} return comment \"$remarks\"" 2>/dev/null
						}

						[ "$tcp_no_redir_ports" != "disable" ] && {
							nft "add rule inet fw4 $nft_prerouting_chain ${_ipt_source} ip protocol tcp $(factor $tcp_no_redir_ports "tcp dport") counter return comment \"$remarks\""
							nft "add rule inet fw4 PSW_MANGLE_V6 comment ${_ipt_source} meta l4proto tcp tcp dport {$tcp_no_redir_ports} counter return comment \"$remarks\""
							msg2="${msg2}[$?]Except ${tcp_no_redir_ports}"
						}
						msg2="${msg2}all ports"

						[ "$tcp_proxy_drop_ports" != "disable" ] && {
							[ "$PROXY_IPV6" == "1" ] && {
								nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"$remarks\"" 2>/dev/null
								nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"$remarks\"" 2>/dev/null
								[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") $(get_nftset_ipv6 $tcp_proxy_mode) counter drop comment \"$remarks\"" 2>/dev/null
							}
							nft "add rule inet fw4 $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\""
							nft "add rule inet fw4 $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"$remarks\""
							nft "add rule inet fw4 $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"$remarks\""
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 $nft_prerouting_chain ip protocol tcp ${_ipt_source} $(factor $tcp_proxy_drop_ports "tcp dport") $(get_nftset_ipv4 $tcp_proxy_mode) counter drop comment \"$remarks\""
							msg2="${msg2}[$?], block proxy TCP port: ${tcp_proxy_drop_ports}"
						}

						if [ -z "${is_tproxy}" ]; then
							nft "add rule inet fw4 PSW_NAT ${_ipt_source} ip daddr $FAKE_IP $(REDIRECT $tcp_port) comment \"$remarks\""
							nft "add rule inet fw4 PSW_NAT ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST $(REDIRECT $tcp_port) comment \"$remarks\""
							nft "add rule inet fw4 PSW_NAT ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST $(REDIRECT $tcp_port) comment \"$remarks\""
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_NAT ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") $(get_redirect_ipv4 $tcp_proxy_mode $tcp_port) comment \"$remarks\""
						else
							nft "add rule inet fw4 PSW_MANGLE ip protocol tcp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW_RULE comment \"$remarks\""
							nft "add rule inet fw4 PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"$remarks\""
							nft "add rule inet fw4 PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"$remarks\" "
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE ip protocol tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") $(get_nftset_ipv4 $tcp_proxy_mode) counter jump PSW_RULE comment \"$remarks\""
							nft "add rule inet fw4 PSW_MANGLE meta nfproto {ipv4} meta l4proto tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY4) comment \"$remarks\""
						fi

						[ "$PROXY_IPV6" == "1" ] && {
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "$tcp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(factor $tcp_redir_ports "tcp dport") $(get_nftset_ipv6 $tcp_proxy_mode) jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} $(REDIRECT $tcp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg} does not proxy TCP"
					fi
					echolog "- ${msg2}"
				}

				nft "add rule inet fw4 $nft_prerouting_chain ip protocol tcp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null

				[ "$udp_proxy_drop_ports" != "disable" ] && {
					[ "$PROXY_IPV6" == "1" ] && {
						nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"$remarks\"" 2>/dev/null
						nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"$remarks\"" 2>/dev/null
						[ "$udp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") $(get_nftset_ipv6 $udp_proxy_mode) counter drop comment \"$remarks\"" 2>/dev/null
					}
					nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr $FAKE_IP counter drop comment \"$remarks\"" 2>/dev/null
					nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"$remarks\"" 2>/dev/null
					nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"$remarks\"" 2>/dev/null
					[ "$udp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_proxy_drop_ports "udp dport") $(get_nftset_ipv4 $udp_proxy_mode) counter drop comment \"$remarks\"" 2>/dev/null
					msg2="${msg2}[$?], block proxy UDP port: ${udp_proxy_drop_ports}"
				}

				[ -n "$udp_port" ] && {
					if [ "$udp_proxy_mode" != "disable" ]; then
						msg2="${msg}Use UDP node [$udp_node_remark] [$(get_action_chain_name $udp_proxy_mode)]"
						msg2="${msg2}(TPROXY:${udp_port})proxy"
						[ "$udp_no_redir_ports" != "disable" ] && {
							nft "add rule inet fw4 PSW_MANGLE meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\""
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_no_redir_ports "udp dport") counter return comment \"$remarks\"" 2>/dev/null
							msg2="${msg2}[$?]Except ${udp_no_redir_ports}"
						}
						msg2="${msg2}all ports"

						nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} ip daddr $FAKE_IP counter jump PSW_RULE comment \"$remarks\""
						nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"$remarks\""
						nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"$remarks\""
						[ "$udp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") $(get_nftset_ipv4 $udp_proxy_mode) jump PSW_RULE comment \"$remarks\""
						nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} $(REDIRECT $udp_port TPROXY4) comment \"$remarks\""

						[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							[ "$udp_proxy_mode" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(factor $udp_redir_ports "udp dport") $(get_nftset_ipv6 $udp_proxy_mode) counter jump PSW_RULE comment \"$remarks\"" 2>/dev/null
							nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} $(REDIRECT $udp_port TPROXY) comment \"$remarks\"" 2>/dev/null
						}
					else
						msg2="${msg} does not proxy UDP"
					fi
					echolog "- ${msg2}"
				}
				nft "add rule inet fw4 PSW_MANGLE ip protocol udp ${_ipt_source} counter return comment \"$remarks\""
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp ${_ipt_source} counter return comment \"$remarks\"" 2>/dev/null
			done
			unset enabled sid remarks sources tcp_proxy_mode udp_proxy_mode tcp_no_redir_ports udp_no_redir_ports tcp_proxy_drop_ports udp_proxy_drop_ports tcp_redir_ports udp_redir_ports tcp_node udp_node
			unset _ip _mac _iprange _ipset _ip_or_mac rule_list tcp_port udp_port tcp_node_remark udp_node_remark
			unset msg msg2
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		#  åŠ è½½TCPé»˜è®¤ä»£ç†æ¨¡å¼
		[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && {
			[ "$PROXY_IPV6" == "1" ] && {
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"é»˜è®¤\""
				[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") $(get_nftset_ipv6 $TCP_PROXY_MODE) counter drop comment \"é»˜è®¤\""
			}

			nft "add inet fw4 $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr $FAKE_IP counter drop comment \"é»˜è®¤\""
			nft "add inet fw4 $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"é»˜è®¤\""
			nft "add inet fw4 $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"é»˜è®¤\""
			[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add inet fw4 $nft_prerouting_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") $(get_nftset_ipv4 $TCP_PROXY_MODE) counter drop comment \"é»˜è®¤\""
		}

		if [ "$TCP_PROXY_MODE" != "disable" ]; then
			[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
				nft add rule inet fw4 $nft_prerouting_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"é»˜è®¤\"
				nft add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return comment \"é»˜è®¤\"
			}
			[ "$TCP_NODE" != "nil" ] && {
				msg="TCP default proxy: use TCP node [$(config_n_get $TCP_NODE remarks)] [$(get_action_chain_name $TCP_PROXY_MODE)]"
				if [ -n "${is_tproxy}" ]; then
					msg="${msg}(TPROXY:${TCP_REDIR_PORT}) proxy"
				else
					msg="${msg}(REDIRECT:${TCP_REDIR_PORT}) Proxy"
				fi
				
				[ "$TCP_NO_REDIR_PORTS" != "disable" ] && msg="${msg} except ${TCP_NO_REDIR_PORTS}"
				msg="${msg}all ports"
				
				[ "$accept_icmp" = "1" ] && {
					nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ip daddr $FAKE_IP $(REDIRECT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_SHUNTLIST $(REDIRECT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp ip daddr @$NFTSET_BLACKLIST $(REDIRECT) comment \"é»˜è®¤\""
					[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp $(get_redirect_ipv4 $TCP_PROXY_MODE) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_ICMP_REDIRECT ip protocol icmp return comment \"é»˜è®¤\""
				}

				[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
					nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNTLIST6 $(REDIRECT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACKLIST6 $(REDIRECT) comment \"é»˜è®¤\""
					[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 $(get_redirect_ipv6 $TCP_PROXY_MODE) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_ICMP_REDIRECT meta l4proto icmpv6 return comment \"é»˜è®¤\""
				}

				if [ -z "${is_tproxy}" ]; then
					nft "add rule inet fw4 PSW_NAT ip protocol tcp ip daddr $FAKE_IP $(REDIRECT $TCP_REDIR_PORT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST $(REDIRECT $TCP_REDIR_PORT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST $(REDIRECT $TCP_REDIR_PORT) comment \"é»˜è®¤\""
					[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_redirect_ipv4 $TCP_PROXY_MODE $TCP_REDIR_PORT) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_NAT ip protocol tcp counter return comment \"é»˜è®¤\""
				else
					nft "add rule inet fw4 PSW_MANGLE ip protocol tcp ip daddr $FAKE_IP counter jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"é»˜è®¤\""
					[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_nftset_ipv4 $TCP_PROXY_MODE) jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE meta l4proto tcp $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE ip protocol tcp counter return comment \"é»˜è®¤\""
				fi

				[ "$PROXY_IPV6" == "1" ] && {
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"é»˜è®¤\""
					[ "$TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_nftset_ipv6 $TCP_PROXY_MODE) jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp counter return comment \"é»˜è®¤\""
				}

				echolog "${msg}"
			}
		fi

		#  åŠ è½½UDPé»˜è®¤ä»£ç†æ¨¡å¼
		[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && {
			[ "$PROXY_IPV6" == "1" ] && {
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter drop comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter drop comment \"é»˜è®¤\""
				[ "$UDP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") $(get_nftset_ipv6 $UDP_PROXY_MODE) counter drop comment \"é»˜è®¤\""
			}
			nft "add rule inet fw4 PSW_MANGLE $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr $FAKE_IP counter drop comment \"é»˜è®¤\""
			nft "add rule inet fw4 PSW_MANGLE $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_SHUNTLIST counter drop comment \"é»˜è®¤\""
			nft "add rule inet fw4 PSW_MANGLE $(factor $UDP_PROXY_DROP_PORTS "udp dport") ip daddr @$NFTSET_BLACKLIST counter drop comment \"é»˜è®¤\""
			[ "$UDP_PROXY_MODE" != "direct/proxy" ] && nft "add inet fw4 PSW_MANGLE ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") $(get_nftset_ipv4 $UDP_PROXY_MODE) counter drop comment \"é»˜è®¤\""
		}
		if [ "$UDP_PROXY_MODE" != "disable" ]; then
			[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
				nft "add inet fw4 PSW_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"é»˜è®¤\""
				nft "add inet fw4 PSW_MANGLE_V6 counter meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return comment \"é»˜è®¤\""
			}

			[ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ] && {
				[ "$TCP_UDP" = "1" ] && [ "$UDP_NODE" = "nil" ] && UDP_NODE=$TCP_NODE
				msg="UDP default proxy: Use UDP node [$(config_n_get $UDP_NODE remarks)] [$(get_action_chain_name $UDP_PROXY_MODE)](TPROXY:${UDP_REDIR_PORT}) proxy"

				[ "$UDP_NO_REDIR_PORTS" != "disable" ] && msg="${msg} except ${UDP_NO_REDIR_PORTS}"
				msg="${msg}all ports"

				nft "add rule inet fw4 PSW_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_SHUNTLIST counter jump PSW_RULE comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") ip daddr @$NFTSET_BLACKLIST counter jump PSW_RULE comment \"é»˜è®¤\""
				[ "$UDP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") $(get_nftset_ipv4 $UDP_PROXY_MODE) jump PSW_RULE comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE meta l4proto udp $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"é»˜è®¤\""
				nft "add rule inet fw4 PSW_MANGLE ip protocol udp counter return comment \"é»˜è®¤\""

				[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_SHUNTLIST6 counter jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") ip6 daddr @$NFTSET_BLACKLIST6 counter jump PSW_RULE comment \"é»˜è®¤\""
					[ "$UDP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") $(get_nftset_ipv6 $UDP_PROXY_MODE) jump PSW_RULE comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"é»˜è®¤\""
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp counter return comment \"é»˜è®¤\""
				}

				echolog "${msg}"
				udp_flag=1
			}
		fi
	}
}

filter_haproxy() {
	for item in ${haproxy_items}; do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		insert_nftset $NFTSET_VPSLIST 0 $ip
	done
	echolog "Add load balancing nodes to nftset[$NFTSET_VPSLIST] direct connection completed"
}

filter_vps_addr() {
	for server_host in $@; do
		local vps_ip4=$(get_host_ip "ipv4" ${server_host})
		local vps_ip6=$(get_host_ip "ipv6" ${server_host})
		[ -n "$vps_ip4" ] && insert_nftset $NFTSET_VPSLIST 0 $vps_ip4
		[ -n "$vps_ip6" ] && insert_nftset $NFTSET_VPSLIST6 0 $vps_ip6
	done
}

filter_vpsip() {
	insert_nftset $NFTSET_VPSLIST 0 $(uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sed -e "/^$/d")
	insert_nftset $NFTSET_VPSLIST6 0 $(uci show $CONFIG | grep ".address=" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "/^$/d")
	echolog "Add all nodes to nftset[$NFTSET_VPSLIST] direct connection completed"
}

filter_node() {
	local proxy_node=${1}
	local stream=$(echo ${2} | tr 'A-Z' 'a-z')
	local proxy_port=${3}

	filter_rules() {
		local node=${1}
		local stream=${2}
		local _proxy=${3}
		local _port=${4}
		local _is_tproxy msg msg2

		if [ -n "$node" ] && [ "$node" != "nil" ]; then
			local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
			local address=$(config_n_get $node address)
			local port=$(config_n_get $node port)
			_is_tproxy=${is_tproxy}
			[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
			if [ -n "${_is_tproxy}" ]; then
				msg="TPROXY"
			else
				msg="REDIRECT"
			fi
		else
			echolog "- The node configuration is abnormal, skip"
			return 0
		fi

		local ADD_INDEX=$FORCE_INDEX
		for _ipt in 4 6; do
			[ "$_ipt" == "4" ] && _ip_type=ip && _set_name=$NFTSET_VPSLIST
			[ "$_ipt" == "6" ] && _ip_type=ip6 && _set_name=$NFTSET_VPSLIST6
			nft "list chain inet fw4 $nft_output_chain" 2>/dev/null | grep -q "${address}:${port}"
			if [ $? -ne 0 ]; then
				unset dst_rule
				local dst_rule="jump PSW_RULE"
				msg2="Routing by rules (${msg})"
				[ -n "${is_tproxy}" ] || {
					dst_rule=$(REDIRECT $_port)
					msg2="Matryoshka use (${msg}:${port} -> ${_port})"
				}
				[ -n "$_proxy" ] && [ "$_proxy" == "1" ] && [ -n "$_port" ] || {
					ADD_INDEX=$(RULE_LAST_INDEX "inet fw4" $nft_output_chain $_set_name $FORCE_INDEX)
					dst_rule="return"
					msg2="Direct proxy"
				}
				nft "insert rule inet fw4 $nft_output_chain position $ADD_INDEX meta l4proto $stream $_ip_type daddr $address $stream dport $port $dst_rule comment \"${address}:${port}\"" 2>/dev/null
			else
				msg2="Configured node,"
			fi
		done
		msg="[$?]$(echo ${2} | tr 'a-z' 'A-Z')${msg2} uses chain ${ADD_INDEX}, node (${type}): ${address}:$ {port}"
		#echolog "  - ${msg}"
	}

	local proxy_protocol=$(config_n_get $proxy_node protocol)
	local proxy_type=$(echo $(config_n_get $proxy_node type nil) | tr 'A-Z' 'a-z')
	[ "$proxy_type" == "nil" ] && echolog "- The node configuration is abnormal, skip!: ${proxy_node}" && return 0
	if [ "$proxy_protocol" == "_balancing" ]; then
		#echolog "  - å¤šèŠ‚ç‚¹è´Ÿè½½å‡è¡¡ï¼ˆ${proxy_type}ï¼‰..."
		proxy_node=$(config_n_get $proxy_node balancing_node)
		for _node in $proxy_node; do
			filter_rules "$_node" "$stream"
		done
	elif [ "$proxy_protocol" == "_shunt" ]; then
		#echolog "  - æŒ‰è¯·æ±‚ç›®çš„åœ°å€åˆ†æµï¼ˆ${proxy_type}ï¼‰..."
		local default_node=$(config_n_get $proxy_node default_node _direct)
		local main_node=$(config_n_get $proxy_node main_node nil)
		if [ "$main_node" != "nil" ]; then
			filter_rules $main_node $stream
		else
			if [ "$default_node" != "_direct" ] && [ "$default_node" != "_blackhole" ]; then
				filter_rules $default_node $stream
			fi
		fi
:<<!
		local default_node_address=$(get_host_ip ipv4 $(config_n_get $default_node address) 1)
		local default_node_port=$(config_n_get $default_node port)

		local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		for shunt_id in $shunt_ids; do
			#local shunt_proxy=$(config_n_get $proxy_node "${shunt_id}_proxy" 0)
			local shunt_proxy=0
			local shunt_node=$(config_n_get $proxy_node "${shunt_id}" nil)
			[ "$shunt_node" != "nil" ] && {
				[ "$shunt_proxy" == 1 ] && {
					local shunt_node_address=$(get_host_ip ipv4 $(config_n_get $shunt_node address) 1)
					local shunt_node_port=$(config_n_get $shunt_node port)
					[ "$shunt_node_address" == "$default_node_address" ] && [ "$shunt_node_port" == "$default_node_port" ] && {
						shunt_proxy=0
					}
				}
				filter_rules "$(config_n_get $proxy_node $shunt_id)" "$stream" "$shunt_proxy" "$proxy_port"
			}
		done
!
	else
		#echolog "  - æ™®é€šèŠ‚ç‚¹ï¼ˆ${proxy_type}ï¼‰..."
		filter_rules "$proxy_node" "$stream"
	fi
}

dns_hijack() {
	nft "add rule inet fw4 dstnat ip protocol udp ip dport 53 redirect to 53"
	echolog "Force forwarding requests for local DNS port UDP/53 [$?]"
}

add_firewall_rule() {
	echolog "Starting loading firewall rules..."
	gen_nftset $NFTSET_VPSLIST ipv4_addr 0 0
	gen_nftset $NFTSET_GFW ipv4_addr "2d" 0
	gen_nftset $NFTSET_LANLIST ipv4_addr 0 0 $(gen_lanlist)
	if [ -f $RULES_PATH/chnroute.nft ] && [ -s $RULES_PATH/chnroute.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute.nft) -ge 8 ]; then
		#echolog "ä½¿ç”¨ç¼“å­˜åŠ è½½chnroute..."
		nft -f $RULES_PATH/chnroute.nft
	else
		gen_nftset $NFTSET_CHN ipv4_addr "2d" 0 $(cat $RULES_PATH/chnroute | tr -s '\n' | grep -v "^#")
	fi
	gen_nftset $NFTSET_BLACKLIST ipv4_addr 0 0 $(cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_WHITELIST ipv4_addr 0 0 $(cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_BLOCKLIST ipv4_addr 0 0 $(cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	gen_nftset $NFTSET_SHUNTLIST ipv4_addr 0 0

	gen_nftset $NFTSET_VPSLIST6 ipv6_addr 0 0
	gen_nftset $NFTSET_GFW6 ipv6_addr "2d" 0
	gen_nftset $NFTSET_LANLIST6 ipv6_addr 0 0 $(gen_lanlist_6)
	if [ -f $RULES_PATH/chnroute6.nft ] && [ -s $RULES_PATH/chnroute6.nft ] && [ $(awk 'END{print NR}' $RULES_PATH/chnroute6.nft) -ge 8 ]; then
		#echolog "ä½¿ç”¨ç¼“å­˜åŠ è½½chnroute6..."
		nft -f $RULES_PATH/chnroute6.nft
	else
		gen_nftset $NFTSET_CHN6 ipv6_addr "2d" 0 $(cat $RULES_PATH/chnroute6 | tr -s '\n' | grep -v "^#")
	fi
	gen_nftset $NFTSET_BLACKLIST6 ipv6_addr 0 0 $(cat $RULES_PATH/proxy_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_WHITELIST6 ipv6_addr 0 0 $(cat $RULES_PATH/direct_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_BLOCKLIST6 ipv6_addr 0 0 $(cat $RULES_PATH/block_ip | tr -s '\n' | grep -v "^#" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	gen_nftset $NFTSET_SHUNTLIST6 ipv6_addr 0 0

	local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')

	for shunt_id in $shunt_ids; do
		insert_nftset $NFTSET_SHUNTLIST 0 $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}")
	done

	for shunt_id in $shunt_ids; do
		insert_nftset $NFTSET_SHUNTLIST6 0 $(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	done

	# å¿½ç•¥ç‰¹æ®ŠIPæ®µ
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#echolog "æœ¬æœºIPv4ç½‘æ®µäº’è®¿ç›´è¿žï¼š${lan_ip}"
		#echolog "æœ¬æœºIPv6ç½‘æ®µäº’è®¿ç›´è¿žï¼š${lan_ip6}"

		[ -n "$lan_ip" ] && insert_nftset $NFTSET_LANLIST 0 $(echo $lan_ip | sed -e "s/ /\n/g")
		[ -n "$lan_ip6" ] && insert_nftset $NFTSET_LANLIST6 0 $(echo $lan_ip6 | sed -e "s/ /\n/g")
	}

	[ -n "$ISP_DNS" ] && {
		#echolog "å¤„ç† ISP DNS ä¾‹å¤–..."
		for ispip in $ISP_DNS; do
			insert_nftset $NFTSET_WHITELIST 0 $ispip >/dev/null 2>&1 &
			#echolog "  - è¿½åŠ åˆ°ç™½åå•ï¼š${ispip}"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		#echolog "å¤„ç† ISP IPv6 DNS ä¾‹å¤–..."
		for ispip6 in $ISP_DNS6; do
			insert_nftset $NFTSET_WHITELIST6 0 $ispip6 >/dev/null 2>&1 &
			#echolog "  - è¿½åŠ åˆ°ç™½åå•ï¼š${ispip6}"
		done
	}

	#  è¿‡æ»¤æ‰€æœ‰èŠ‚ç‚¹IP
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &
	# Prevent some conditions
	filter_vps_addr $(config_n_get $TCP_NODE address) $(config_n_get $UDP_NODE address) > /dev/null 2>&1 &

	accept_icmp=$(config_t_get global_forwarding accept_icmp 0)
	accept_icmpv6=$(config_t_get global_forwarding accept_icmpv6 0)

	local tcp_proxy_way=$(config_t_get global_forwarding tcp_proxy_way redirect)
	if [ "$tcp_proxy_way" = "redirect" ]; then
		unset is_tproxy
		nft_prerouting_chain="PSW_NAT"
		nft_output_chain="PSW_OUTPUT_NAT"
	elif [ "$tcp_proxy_way" = "tproxy" ]; then
		is_tproxy="TPROXY"
		nft_prerouting_chain="PSW_MANGLE"
		nft_output_chain="PSW_OUTPUT_MANGLE"
	fi

	nft "add chain inet fw4 nat_output { type nat hook output priority -1; }"

	nft "add chain inet fw4 PSW_DIVERT"
	nft "flush chain inet fw4 PSW_DIVERT"
	nft "add rule inet fw4 PSW_DIVERT meta l4proto tcp socket transparent 1 mark set 1 counter accept"

	nft "add chain inet fw4 PSW_REDIRECT"
	nft "flush chain inet fw4 PSW_REDIRECT"
	nft "add rule inet fw4 dstnat jump PSW_REDIRECT"

	# for ipv4 ipv6 tproxy mark
	nft "add chain inet fw4 PSW_RULE"
	nft "flush chain inet fw4 PSW_RULE"
	nft "add rule inet fw4 PSW_RULE meta mark set ct mark counter"
	nft "add rule inet fw4 PSW_RULE meta mark 1 counter return"
	nft "add rule inet fw4 PSW_RULE tcp flags &(fin|syn|rst|ack) == syn meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule inet fw4 PSW_RULE meta l4proto udp ct state new meta mark set mark and 0x0 xor 0x1 counter"
	nft "add rule inet fw4 PSW_RULE ct mark set mark counter"

	#ipv4 tproxy mode and udp
	nft "add chain inet fw4 PSW_MANGLE"
	nft "flush chain inet fw4 PSW_MANGLE"
	nft "add rule inet fw4 PSW_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule inet fw4 PSW_MANGLE ip daddr @$NFTSET_VPSLIST counter return"
	nft "add rule inet fw4 PSW_MANGLE ip daddr @$NFTSET_WHITELIST counter return"
	nft "add rule inet fw4 PSW_MANGLE ip daddr @$NFTSET_BLOCKLIST counter drop"

	nft "add chain inet fw4 PSW_OUTPUT_MANGLE"
	nft "flush chain inet fw4 PSW_OUTPUT_MANGLE"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip daddr @$NFTSET_LANLIST counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip daddr @$NFTSET_VPSLIST counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip daddr @$NFTSET_WHITELIST counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE meta mark 0xff counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip daddr @$NFTSET_BLOCKLIST counter drop"

	# jump chains
	nft "add rule inet fw4 mangle_prerouting meta nfproto {ipv4} counter jump PSW_MANGLE"
	insert_rule_before "inet fw4" "mangle_prerouting" "PSW_MANGLE" "counter jump PSW_DIVERT"

	#ipv4 tcp redirect mode
	[ -z "${is_tproxy}" ] && {
		nft "add chain inet fw4 PSW_NAT"
		nft "flush chain inet fw4 PSW_NAT"
		nft "add rule inet fw4 PSW_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule inet fw4 PSW_NAT ip daddr @$NFTSET_VPSLIST counter return"
		nft "add rule inet fw4 PSW_NAT ip daddr @$NFTSET_WHITELIST counter return"
		nft "add rule inet fw4 PSW_NAT ip daddr @$NFTSET_BLOCKLIST counter drop"
		nft "add rule inet fw4 dstnat ip protocol tcp counter jump PSW_NAT"

		nft "add chain inet fw4 PSW_OUTPUT_NAT"
		nft "flush chain inet fw4 PSW_OUTPUT_NAT"
		nft "add rule inet fw4 PSW_OUTPUT_NAT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule inet fw4 PSW_OUTPUT_NAT ip daddr @$NFTSET_VPSLIST counter return"
		nft "add rule inet fw4 PSW_OUTPUT_NAT ip daddr @$NFTSET_WHITELIST counter return"
		nft "add rule inet fw4 PSW_OUTPUT_NAT meta mark 0xff counter return"
		nft "add rule inet fw4 PSW_OUTPUT_NAT ip daddr @$NFTSET_BLOCKLIST counter drop"
	}

	#icmp ipv6-icmp redirect
	if [ "$accept_icmp" = "1" ]; then
		nft "add chain inet fw4 PSW_ICMP_REDIRECT"
		nft "flush chain inet fw4 PSW_ICMP_REDIRECT"
		nft "add rule inet fw4 PSW_ICMP_REDIRECT ip daddr @$NFTSET_LANLIST counter return"
		nft "add rule inet fw4 PSW_ICMP_REDIRECT ip daddr @$NFTSET_VPSLIST counter return"
		nft "add rule inet fw4 PSW_ICMP_REDIRECT ip daddr @$NFTSET_WHITELIST counter return"

		[ "$accept_icmpv6" = "1" ] && {
			nft "add rule inet fw4 PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_LANLIST6 counter return"
			nft "add rule inet fw4 PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_VPSLIST6 counter return"
			nft "add rule inet fw4 PSW_ICMP_REDIRECT ip6 daddr @$NFTSET_WHITELIST6 counter return"
		}

		nft "add rule inet fw4 dstnat meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
		nft "add rule inet fw4 nat_output meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
	fi

	WAN_IP=$(get_wan_ip)
	if [ -n "${WAN_IP}" ]; then
		[ -n "${is_tproxy}" ] && nft "add rule inet fw4 PSW_MANGLE ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\"" || nft "add rule inet fw4 PSW_NAT ip daddr ${WAN_IP} counter return comment \"WAN_IP_RETURN\""
	fi
	unset WAN_IP

	ip rule add fwmark 1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

	#ipv6 tproxy mode and udp
	nft "add chain inet fw4 PSW_MANGLE_V6"
	nft "flush chain inet fw4 PSW_MANGLE_V6"
	nft "add rule inet fw4 PSW_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule inet fw4 PSW_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
	nft "add rule inet fw4 PSW_MANGLE_V6 ip6 daddr @$NFTSET_WHITELIST6 counter return"
	nft "add rule inet fw4 PSW_MANGLE_V6 ip6 daddr @$NFTSET_BLOCKLIST6 counter drop"

	nft "add chain inet fw4 PSW_OUTPUT_MANGLE_V6"
	nft "flush chain inet fw4 PSW_OUTPUT_MANGLE_V6"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_LANLIST6 counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_VPSLIST6 counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_WHITELIST6 counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta mark 0xff counter return"
	nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 ip6 daddr @$NFTSET_BLOCKLIST6 counter drop"

	# jump chains
	[ "$PROXY_IPV6" == "1" ] && {
		nft "add rule inet fw4 mangle_prerouting meta nfproto {ipv6} counter jump PSW_MANGLE_V6"
		nft "add rule inet fw4 mangle_output meta nfproto {ipv6} counter jump PSW_OUTPUT_MANGLE_V6 comment \"PSW_OUTPUT_MANGLE\""

		WAN6_IP=$(get_wan6_ip)
		[ -n "${WAN6_IP}" ] && nft "add rule inet fw4 PSW_MANGLE_V6 ip6 daddr ${WAN6_IP} counter return comment \"WAN6_IP_RETURN\""
		unset WAN6_IP

		ip -6 rule add fwmark 1 table 100
		ip -6 route add local ::/0 dev lo table 100
	}
	
	# è¿‡æ»¤SocksèŠ‚ç‚¹
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		#echolog "åˆ†æž Socks æœåŠ¡æ‰€ä½¿ç”¨èŠ‚ç‚¹..."
		local id enabled node port msg num
		for id in $ids; do
			enabled=$(config_n_get $id enabled 0)
			[ "$enabled" == "1" ] || continue
			node=$(config_n_get $id node nil)
			port=$(config_n_get $id port 0)
			msg="Socks Service [:${port}]"
			if [ "$node" == "nil" ] || [ "$port" == "0" ]; then
				msg="${msg} is not fully configured, skip"
			else
				filter_node $node TCP > /dev/null 2>&1 &
				filter_node $node UDP > /dev/null 2>&1 &
			fi
			#echolog "  - ${msg}"
		done
	}

	[ "$ENABLED_DEFAULT_ACL" == 1 ] && {
		# å¤„ç†è½®æ¢èŠ‚ç‚¹çš„åˆ†æµæˆ–å¥—å¨ƒ
		local node port stream switch
		for stream in TCP UDP; do
			eval "node=\${${stream}_NODE}"
			eval "port=\${${stream}_REDIR_PORT}"
			#echolog "åˆ†æž $stream ä»£ç†è‡ªåŠ¨åˆ‡æ¢..."
			[ "$stream" == "UDP" ] && [ "$node" == "tcp" ] && {
				eval "node=\${TCP_NODE}"
				eval "port=\${TCP_REDIR_PORT}"
			}
			if [ "$node" != "nil" ] && [ "$(config_get_type $node nil)" != "nil" ]; then
				filter_node $node $stream $port > /dev/null 2>&1 &
			fi
		done

		# åŠ è½½è·¯ç”±å™¨è‡ªèº«ä»£ç† TCP
		if [ "$TCP_NODE" != "nil" ]; then
			echolog "Loading the router's own TCP proxy..."

			[ "$accept_icmp" = "1" ] && {
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr $FAKE_IP counter redirect"
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_SHUNTLIST counter redirect"
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo ip protocol icmp ip daddr @$NFTSET_BLACKLIST counter redirect"
				[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo ip protocol icmp $(get_nftset_ipv4 $LOCALHOST_TCP_PROXY_MODE) counter redirect"
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo ip protocol icmp counter return"
			}

			[ "$accept_icmpv6" = "1" ] && {
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_SHUNTLIST6 counter redirect"
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 ip6 daddr @$NFTSET_BLACKLIST6 counter redirect"
				[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 $(get_nftset_ipv6 $LOCALHOST_TCP_PROXY_MODE) counter redirect"
				nft "add rule inet fw4 PSW_ICMP_REDIRECT oif lo meta l4proto icmpv6 counter return"
			}

			[ -n "${is_tproxy}" ] && {
				echolog "- Enable TPROXY mode"
			}

			_proxy_tcp_access() {
				[ -n "${2}" ] || return 0
				nft "get element inet fw4 $NFTSET_LANLIST {${2}}" &>/dev/null
				[ $? -eq 0 ] && {
					echolog "- Upstream DNS server ${2} is already in the list for direct access and does not force forwarding of access to this server's TCP/${3} port to the TCP proxy"
					return 0
				}
				if [ -z "${is_tproxy}" ]; then
					nft add rule inet fw4 PSW_OUTPUT_NAT ip protocol tcp ip daddr ${2} tcp dport ${3} $(REDIRECT $TCP_REDIR_PORT)
				else
					nft add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol tcp ip daddr ${2} tcp dport ${3} counter jump PSW_RULE
					nft add rule inet fw4 PSW_MANGLE iif lo tcp dport ${3} ip daddr ${2} $(REDIRECT $TCP_REDIR_PORT TPROXY4) comment \"æœ¬æœº\"
				fi
				echolog "- [$?]Add the upstream DNS server ${2}:${3} to the TCP forwarding chain of the router's own proxy"
			}

			[ "$use_tcp_node_resolve_dns" == 1 ] && hosts_foreach REMOTE_DNS _proxy_tcp_access 53
			[ "$TCP_NO_REDIR_PORTS" != "disable" ] && {
				nft "add rule inet fw4 $nft_output_chain ip protocol tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
				nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_NO_REDIR_PORTS "tcp dport") counter return"
				echolog "- [$?]Do not proxy TCP port: $TCP_NO_REDIR_PORTS"
			}
			[ "$TCP_PROXY_DROP_PORTS" != "disable" ] && [ "$LOCALHOST_TCP_PROXY_MODE" != "disable" ] && {
				nft add rule inet fw4 $nft_output_chain ip protocol tcp ip daddr $FAKE_IP $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				nft add rule inet fw4 $nft_output_chain ip protocol tcp ip daddr @$NFTSET_SHUNTLIST $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				nft add rule inet fw4 $nft_output_chain ip protocol tcp ip daddr @$NFTSET_BLACKLIST $(factor $TCP_PROXY_DROP_PORTS "tcp dport") counter drop
				[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft add rule inet fw4 $nft_output_chain ip protocol tcp $(factor $TCP_PROXY_DROP_PORTS "tcp dport") $(get_nftset_ipv4 $LOCALHOST_TCP_PROXY_MODE) counter drop
				echolog "- [$?], blocking proxy TCP port: $TCP_PROXY_DROP_PORTS"
			}

			if [ -z "${is_tproxy}" ]; then
				[ "$LOCALHOST_TCP_PROXY_MODE" != "disable" ] && {
					nft "add rule inet fw4 PSW_OUTPUT_NAT ip protocol tcp ip daddr $FAKE_IP $(REDIRECT $TCP_REDIR_PORT)"
					nft "add rule inet fw4 PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_SHUNTLIST counter $(REDIRECT $TCP_REDIR_PORT)"
					nft "add rule inet fw4 PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") ip daddr @$NFTSET_BLACKLIST counter $(REDIRECT $TCP_REDIR_PORT)"
					[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_OUTPUT_NAT ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_redirect_ipv4 $LOCALHOST_TCP_PROXY_MODE $TCP_REDIR_PORT)"
				}
				nft "add rule inet fw4 nat_output ip protocol tcp counter jump PSW_OUTPUT_NAT"
			else
				[ "$LOCALHOST_TCP_PROXY_MODE" != "disable" ] && {
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol tcp ip daddr $FAKE_IP counter jump PSW_RULE"
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_SHUNTLIST $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol tcp ip daddr @$NFTSET_BLACKLIST $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_nftset_ipv4 $LOCALHOST_TCP_PROXY_MODE) jump PSW_RULE"
					nft "add rule inet fw4 PSW_MANGLE meta l4proto tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"æœ¬æœº\""
				}
				nft "add rule inet fw4 PSW_MANGLE ip protocol tcp iif lo counter return comment \"æœ¬æœº\""
				nft "add rule inet fw4 mangle_output meta nfproto {ipv4} meta l4proto tcp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
			fi

			[ "$PROXY_IPV6" == "1" ] && {
				[ "$LOCALHOST_TCP_PROXY_MODE" != "disable" ] && {
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_SHUNTLIST6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto tcp ip6 daddr @$NFTSET_BLACKLIST6 $(factor $TCP_REDIR_PORTS "tcp dport") counter jump PSW_RULE"
					[ "$LOCALHOST_TCP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto tcp $(factor $TCP_REDIR_PORTS "tcp dport") $(get_nftset_ipv6 $LOCALHOST_TCP_PROXY_MODE) jump PSW_RULE"
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp iif lo $(REDIRECT $TCP_REDIR_PORT TPROXY) comment \"æœ¬æœº\""
				}
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto tcp iif lo counter return comment \"æœ¬æœº\""
			}
		fi

		# åŠ è½½è·¯ç”±å™¨è‡ªèº«ä»£ç† UDP
		[ "$UDP_PROXY_DROP_PORTS" != "disable" ] && [ "$LOCALHOST_UDP_PROXY_MODE" != "disable" ] && {
			nft add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
			nft add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNTLIST $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
			nft add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACKLIST $(factor $UDP_PROXY_DROP_PORTS "udp dport") counter drop
			[ "$LOCALHOST_UDP_PROXY_MODE" != "direct/proxy" ] && nft add rule inet fw4 PSW_OUTPUT_MANGLE counter ip protocol udp $(factor $UDP_PROXY_DROP_PORTS "udp dport") $(get_nftset_ipv4 $LOCALHOST_UDP_PROXY_MODE) counter drop
			echolog "- [$?], blocking proxy UDP port: $UDP_PROXY_DROP_PORTS"
		}
		if [ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ]; then
			echolog "Loading the router's own UDP proxy..."
			_proxy_udp_access() {
				[ -n "${2}" ] || return 0
				nft "get element inet fw4 $NFTSET_LANLIST {${2}}" &>/dev/null
				[ $? == 0 ] && {
					echolog "- Upstream DNS server ${2} is already in the list for direct access and does not force forwarding of access to this server's UDP/${3} port to the UDP proxy"
					return 0
				}
				nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr ${2} udp dport ${3} counter jump PSW_RULE"
				nft "add rule inet fw4 PSW_MANGLE iif lo meta l4proto udp ip daddr ${2} $(REDIRECT $UDP_REDIR_PORT TPROXY4) comment \"æœ¬æœº\""
				echolog "- [$?]Add the upstream DNS server ${2}:${3} to the UDP forwarding chain of the router's own proxy"
			}
			[ "$use_udp_node_resolve_dns" == 1 ] && hosts_foreach REMOTE_DNS _proxy_udp_access 53
			[ "$UDP_NO_REDIR_PORTS" != "disable" ] && {
				nft add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return
				nft add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_NO_REDIR_PORTS "udp dport") counter return
				echolog "- [$?]Do not proxy UDP ports: $UDP_NO_REDIR_PORTS"
			}

			[ "$LOCALHOST_UDP_PROXY_MODE" != "disable" ] && {
				nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr $FAKE_IP counter jump PSW_RULE"
				nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_SHUNTLIST $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp ip daddr @$NFTSET_BLACKLIST $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
				[ "$LOCALHOST_UDP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_OUTPUT_MANGLE ip protocol udp $(factor $UDP_REDIR_PORTS "udp dport") $(get_nftset_ipv4 $LOCALHOST_UDP_PROXY_MODE) jump PSW_RULE"
				nft "add rule inet fw4 PSW_MANGLE meta l4proto udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"æœ¬æœº\""
			}
			nft "add rule inet fw4 PSW_MANGLE ip protocol udp iif lo counter return comment \"æœ¬æœº\""
			nft "add rule inet fw4 mangle_output meta nfproto {ipv4} meta l4proto udp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""

			[ "$PROXY_IPV6" == "1" ] && [ "$PROXY_IPV6_UDP" == "1" ] && {
				[ "$LOCALHOST_UDP_PROXY_MODE" != "disable" ] && {
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_SHUNTLIST6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto udp ip6 daddr @$NFTSET_BLACKLIST6 $(factor $UDP_REDIR_PORTS "udp dport") counter jump PSW_RULE"
					[ "$LOCALHOST_UDP_PROXY_MODE" != "direct/proxy" ] && nft "add rule inet fw4 PSW_OUTPUT_MANGLE_V6 meta l4proto udp $(factor $UDP_REDIR_PORTS "udp dport") $(get_nftset_ipv6 $LOCALHOST_UDP_PROXY_MODE) jump PSW_RULE"
					nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp iif lo $(REDIRECT $UDP_REDIR_PORT TPROXY) comment \"æœ¬æœº\""
				}
				nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp iif lo counter return comment \"æœ¬æœº\""
			}
		fi

		nft "add rule inet fw4 mangle_output oif lo counter return comment \"PSW_OUTPUT_MANGLE\""
		nft "add rule inet fw4 mangle_output meta mark 1 counter return comment \"PSW_OUTPUT_MANGLE\""

		nft "add rule inet fw4 PSW_MANGLE ip protocol udp udp dport 53 counter return"
		nft "add rule inet fw4 PSW_MANGLE_V6 meta l4proto udp udp dport 53 counter return"
	}

	#  åŠ è½½ACLS
	load_acl
	
	for iface in $(ls ${TMP_IFACE_PATH}); do
		nft "insert rule inet fw4 $nft_output_chain oif $iface counter return"
		nft "insert rule inet fw4 PSW_OUTPUT_MANGLE_V6 oif $iface counter return"
	done

	[ -n "${is_tproxy}" -o -n "${udp_flag}" ] && {
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		echo -n $bridge_nf_ipt > $TMP_PATH/bridge_nf_ipt
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			echo -n $bridge_nf_ip6t > $TMP_PATH/bridge_nf_ip6t
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	}
	echolog "Firewall rules loading completed!"
}

del_firewall_rule() {
	for nft in "forward" "dstnat" "srcnat" "nat_output" "mangle_prerouting" "mangle_output"; do
        local handles=$(nft -a list chain inet fw4 ${nft} 2>/dev/null | grep -E "PSW_" | awk -F '# handle ' '{print$2}')
		for handle in $handles; do
			nft delete rule inet fw4 ${nft} handle ${handle} 2>/dev/null
		done
	done

	for handle in $(nft -a list chains | grep -E "chain PSW_" | grep -v "PSW_RULE" | awk -F '# handle ' '{print$2}'); do
		nft delete chain inet fw4 handle ${handle} 2>/dev/null
	done

	# Need to be removed at the end, otherwise it will show "Resource busy"
	nft delete chain inet fw4 handle $(nft -a list chains | grep -E "PSW_RULE" | awk -F '# handle ' '{print$2}') 2>/dev/null

	ip rule del fwmark 1 lookup 100 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null

	ip -6 rule del fwmark 1 table 100 2>/dev/null
	ip -6 route del local ::/0 dev lo table 100 2>/dev/null

	destroy_nftset $NFTSET_LANLIST
	destroy_nftset $NFTSET_VPSLIST
	#destroy_nftset $NFTSET_SHUNTLIST
	#destroy_nftset $NFTSET_GFW
	#destroy_nftset $NFTSET_CHN
	#destroy_nftset $NFTSET_BLACKLIST
	destroy_nftset $NFTSET_BLOCKLIST
	destroy_nftset $NFTSET_WHITELIST

	destroy_nftset $NFTSET_LANLIST6
	destroy_nftset $NFTSET_VPSLIST6
	#destroy_nftset $NFTSET_SHUNTLIST6
	#destroy_nftset $NFTSET_GFW6
	#destroy_nftset $NFTSET_CHN6
	#destroy_nftset $NFTSET_BLACKLIST6
	destroy_nftset $NFTSET_BLOCKLIST6
	destroy_nftset $NFTSET_WHITELIST6

	$DIR/app.sh echolog "Deletion of relevant firewall rules completed."
}

flush_nftset() {
	del_firewall_rule
	for _name in $(nft -a list sets | grep -E "passwall" | awk -F 'set ' '{print $2}' | awk '{print $1}'); do
		destroy_nftset ${_name}
	done
	rm -rf /tmp/singbox_passwall*
	rm -rf /tmp/etc/passwall_tmp/dnsmasq*
	/etc/init.d/passwall reload
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	local nft_chain_file=$TMP_PATH/PSW_RULE.nft
	local nft_set_file=$TMP_PATH/PSW_SETS.nft
	echo "#!/usr/sbin/nft -f" > $nft_chain_file
	echo "#!/usr/sbin/nft -f" > $nft_set_file
	for chain in $(nft -a list chains | grep -E "chain PSW_" | awk -F ' ' '{print$2}'); do
		nft list chain inet fw4 ${chain} >> $nft_chain_file
	done

	for set_name in $(nft -a list sets | grep -E "set passwall_" | awk -F ' ' '{print$2}'); do
		nft list set inet fw4 ${set_name} >> $nft_set_file
	done

	local __nft=" "
	__nft=$(cat <<- EOF

		[ -z "\$(nft list sets 2>/dev/null | grep "passwall_")" ] && nft -f ${nft_set_file}
		[ -z "\$(nft list chain inet fw4 nat_output 2>/dev/null)" ] && nft "add chain inet fw4 nat_output { type nat hook output priority -1; }"
		nft -f ${nft_chain_file}

		nft "add rule inet fw4 dstnat jump PSW_REDIRECT"

		[ "$accept_icmp" == "1" ] && {
			nft "add rule inet fw4 dstnat meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
			nft "add rule inet fw4 nat_output meta l4proto {icmp,icmpv6} counter jump PSW_ICMP_REDIRECT"
		}

		[ -z "${is_tproxy}" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "inet fw4" PSW_NAT WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule inet fw4 PSW_NAT handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
			fi
			nft "add rule inet fw4 dstnat ip protocol tcp counter jump PSW_NAT"
			nft "add rule inet fw4 nat_output ip protocol tcp counter jump PSW_OUTPUT_NAT"
		}

		[ -n "${is_tproxy}" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "inet fw4" PSW_MANGLE WAN_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN_IP=\$(sh ${MY_PATH} get_wan_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule inet fw4 PSW_MANGLE handle \$PR_INDEX ip daddr "\${WAN_IP}" counter return comment \"WAN_IP_RETURN\""
			fi
			nft "add rule inet fw4 mangle_prerouting meta nfproto {ipv4} counter jump PSW_MANGLE"
			nft "add rule inet fw4 mangle_output meta nfproto {ipv4} meta l4proto tcp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""
		}
		\$(sh ${MY_PATH} insert_rule_before "inet fw4" "mangle_prerouting" "PSW_MANGLE" "counter jump PSW_DIVERT")

		[ "$UDP_NODE" != "nil" -o "$TCP_UDP" = "1" ] && nft "add rule inet fw4 mangle_output meta nfproto {ipv4} meta l4proto udp counter jump PSW_OUTPUT_MANGLE comment \"PSW_OUTPUT_MANGLE\""

		[ "$PROXY_IPV6" == "1" ] && {
			PR_INDEX=\$(sh ${MY_PATH} RULE_LAST_INDEX "inet fw4" PSW_MANGLE_V6 WAN6_IP_RETURN -1)
			if [ \$PR_INDEX -ge 0 ]; then
				WAN6_IP=\$(sh ${MY_PATH} get_wan6_ip)
				[ ! -z "\${WAN_IP}" ] && nft "replace rule inet fw4 PSW_MANGLE_V6 handle \$PR_INDEX ip6 daddr "\${WAN6_IP}" counter return comment \"WAN6_IP_RETURN\""
			fi
			nft "add rule inet fw4 mangle_prerouting meta nfproto {ipv6} counter jump PSW_MANGLE_V6"
			nft "add rule inet fw4 mangle_output meta nfproto {ipv6} counter jump PSW_OUTPUT_MANGLE_V6 comment \"PSW_OUTPUT_MANGLE\""
		}

		nft "add rule inet fw4 mangle_output oif lo counter return comment \"PSW_OUTPUT_MANGLE\""
		nft "add rule inet fw4 mangle_output meta mark 1 counter return comment \"PSW_OUTPUT_MANGLE\""
	EOF
	)

	cat <<-EOF >> $FWI
	${__nft}
	EOF
	return 0
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	add_firewall_rule
	gen_include
}

stop() {
	del_firewall_rule
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
flush_nftset)
	flush_nftset
	;;
get_wan_ip)
	get_wan_ip
	;;
get_wan6_ip)
	get_wan6_ip
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
