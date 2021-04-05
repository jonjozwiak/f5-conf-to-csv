#!/usr/local/bin/python3
#######################################################################################
# This script will parse the bigip.conf from an LTM
# and extract useful data out of it.
#
# USAGE: ./f5-conf-to-csv.py
#
# This requires python 3.9+ due to use of removeprefix
#
#######################################################################################

import re
import sqlite3
import sys
import csv
import pandas as pd

# Default Values
F5_db = 'F5.sqlite3'
nodes={}

def write_csv(conn,query,filename):
    db_print = pd.read_sql_query(query, conn)
    db_print.to_csv(filename, index=False)
    print("Writing file {}".format(filename))

def get_stanza_end(lines,idx,leading_spaces):
    end_idx = idx
    #print("idx: {}, leading_spaces: {}".format(idx,leading_spaces))
    for i in range(idx, len(lines)):
        text_size = leading_spaces + 1
        if lines[i].startswith("}".rjust(text_size, ' ')):
            return end_idx
        end_idx += 1

def create_and_clear_table(cur,table,columns):
    #Create table if does not exist already, else delete contents.
    print("Creating and Wiping Table {}".format(table))
    cur.execute('CREATE TABLE IF NOT EXISTS {tn} ({col})'\
        .format(tn=table, col=columns))
    cur.execute('DELETE FROM {tn}'\
        .format(tn=table))

def get_element(lines,idx,eidx,v):
    element_idx = idx + eidx
    leading_spaces = len(v) - len(v.lstrip())
    element_end_idx = get_stanza_end(lines,element_idx,leading_spaces)
    element_stanza = lines[element_idx+1:element_end_idx]
    elements_stripped = []
    for i, e in enumerate(element_stanza):
        elements_stripped.append(e.strip())
    elements = "; ".join(elements_stripped)
    return elements

# Initialize Database
conn = sqlite3.connect(F5_db)
print("Opened database successfully");
print("Database File:", F5_db)

cur = conn.cursor()
create_and_clear_table(cur, "Nodes", "Name, Address")
create_and_clear_table(cur, "Pools", "Name, Member_Name, Member_Address, Monitor, LB_Mode")
create_and_clear_table(cur, "VirtualServers", "Name, Description, Destination, IP_Forward, IP_Protocol, Mask, Pool, Profiles, Rules, Persist, Source, Source_Address_Translation, Translate_Address, Translate_port")
create_and_clear_table(cur, "VirtualAddresses", "Name, Address, Arp, Mask, Icmp_Echo, Traffic_Group,Spanning")
create_and_clear_table(cur, "Monitors", "Name, Type, Adaptive, Defaults_From, Destination, Interval, IP_DSCP, Recv, Recv_Disable, Send, Time_Until_Up, Timeout, Cipher_List, Compatibility")
create_and_clear_table(cur, "Persistence", "Name, Type, Always_Send, App_Service, Cookie_Encryption, Cookie_name, Defaults_From, Encrypt_Cookie_Poolname, Expiration, Hash_Length, Hash_Offset, HTTP_Only, Mask, Match_Across_Pools, Match_Across_Services, Match_Across_Virtuals, Method, Mirror, Override_Connection_Limit, Secure, Timeout")
create_and_clear_table(cur, "Profiles", "Name, Type, App_Service, Cache_Aging_Rate, Cache_Client_Cache_Control_Mode, Cache_Insert_Age_Header, Cache_Max_Age, Cache_Max_Entries, Cache_Object_Min_Size, Cache_Object_Max_Size, Cache_Size, Cache_Uri_Exclude, Cache_Uri_Include, Cache_Uri_Include_Override, Cache_Uri_Pinned, Cert, Chain, Cipher_Group, Ciphers, Defaults_From, ECN, Idle_Timeout, Inherit_CertKeyChain, Key, Metadata_Cache_Max_Size, Options, Passphrase, Port,Proxy_Buffer_Low, Proxy_Buffer_High, Receive_Window_Size, Send_Buffer_Size")
create_and_clear_table(cur, "Rules", "Name, Rule")

#Call BigIP Conf File
File = open("bigip.conf", "r")
lines = [line.rstrip() for line in File]


for idx, val in enumerate(lines):
    if val.startswith("ltm node"):
        node = val.removeprefix("ltm node ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        address = ""
        for line in stanza:
            if "address" in line:
                address = line.strip().lstrip("address ")
        cur.execute("INSERT INTO Nodes (Name, Address) VALUES (?,?)", (node,address));

    elif val.startswith("ltm virtual-address"):
        address_name = val.removeprefix("ltm virtual-address ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        address, arp, mask, icmp_echo, traffic_group, spanning = "", "", "", "", "", ""
        for line in stanza:
            if "address" in line:
                address = line.strip().lstrip("address").strip()
            elif "arp" in line:
                arp = line.strip().lstrip("arp").strip()
            elif "icmp-echo" in line:
                 icmp_echo = line.strip().lstrip("icmp-echo").strip()
            elif "mask" in line:
                 mask = line.strip().lstrip("mask").strip()
            elif "spanning" in line:
                 spanning = line.strip().lstrip("spanning").strip()
            elif "traffic-group" in line:  
                 traffic_group = line.strip().lstrip("traffic-group").strip()

        cur.execute("INSERT INTO VirtualAddresses (Name, Address, Arp, Mask, Icmp_Echo, Traffic_Group,Spanning) VALUES (?,?,?,?,?,?,?)", (address_name, address, arp, mask, icmp_echo, traffic_group, spanning));
    elif val.startswith("ltm pool"):
        pool = val.lstrip("ltm pool ").rstrip(" {")
        if "}" in val:
            cur.execute("INSERT INTO Pools (Name, Member_Name, Member_Address, Monitor, LB_Mode) VALUES (?,?,?,?,?)", (pool,'','','',''));
        else: 
            leading_spaces = len(val) - len(val.lstrip())
            end_idx = get_stanza_end(lines,idx,leading_spaces)
            stanza = lines[idx:end_idx]
            members = []
            mode = ''
            monitor = ''
            for i, v in enumerate(stanza):
                if "members" in v:
                    members_idx = idx + i
                    leading_spaces = len(v) - len(v.lstrip())
                    members_end_idx = get_stanza_end(lines,members_idx,leading_spaces)
                    members_stanza = lines[members_idx:members_end_idx]
                    for l in members_stanza:
                        if "{" in l:
                            member = l.strip().rstrip(" {") 
                        elif "address" in l:
                            address = l.strip().lstrip("address").strip()
                            members.append({"member" : member, "address" : address})
                elif "monitor" in v:
                    monitor = v.strip().lstrip("monitor ")
                elif "load-balancing-mode" in v:
                    mode = v.strip().lstrip("load-balancing-mode").strip()

            # Write records to the database
            if members == []:
                cur.execute("INSERT INTO Pools (Name, Member_Name, Member_Address, Monitor, LB_Mode) VALUES (?,?,?,?,?)", (pool,'','','',mode));
            else: 
                for m in members:
                    cur.execute("INSERT INTO Pools (Name, Member_Name, Member_Address, Monitor, LB_Mode) VALUES (?,?,?,?,?)", (pool,m["member"],m["address"],monitor,mode));

    elif val.startswith("ltm virtual "):
        virtual_server = val.removeprefix("ltm virtual ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        description = ""
        destination = "" 
        ip_forward = ""
        ip_protocol = ""
        mask = ""
        pool = ""
        profiles = ""
        rules = ""
        persist = ""
        source = ""
        source_address_translation = ""
        translate_address = ""
        translate_port = ""
        for i, v in enumerate(stanza):
            if "description" in v:
                description = v.strip().lstrip("description").strip()
            elif "destination" in v:
                destination = v.strip().lstrip("destination").strip()
            elif "ip-forward" in v:
                ip_forward = "True"
            elif "ip-protocol" in v:
                ip_protocol = v.strip().lstrip("ip-protocol").strip()
            elif "mask" in v: 
                mask = v.strip().lstrip("mask").strip()
            elif "pool" in v:
                pool = v.strip().lstrip("pool").strip()
            elif "profiles" in v:
                profiles = get_element(lines,idx,i,v)
            elif "rules" in v:
                rules = get_element(lines,idx,i,v)
            elif "persist" in v:
                persist = get_element(lines,idx,i,v)
            elif "source-address-translation" in v:
                source_address_translation = get_element(lines,idx,i,v)
            elif "source" in v:
                source = v.strip().lstrip("source").strip()
            elif "translate-address" in v:
                translate_address = v.strip().lstrip("translate-address").strip()
            elif "translate-port" in v:
                translate_port = v.strip().lstrip("translate-port").strip()

        cur.execute("INSERT INTO VirtualServers (Name, Description, Destination, IP_Forward, IP_Protocol, Mask, Pool, Profiles, Rules, Persist, Source, Source_Address_Translation, Translate_Address, Translate_port) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (virtual_server,description,destination,ip_forward,ip_protocol,mask,pool,profiles,rules,persist,source,source_address_translation,translate_address,translate_port));


    elif val.startswith("ltm monitor"):
        m = val.removeprefix("ltm monitor ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        mlist = m.split(" ")
        monitor = mlist[1]
        type = mlist[0]
        adaptive = ""
        cipherlist = ""
        compatibility = ""
        defaults_from = ""
        destination = ""
        interval = ""
        ip_dscp = ""
        recv_disable = ""
        recv = ""
        send = ""
        time_until_ip = ""
        timeout = ""
        for i, v in enumerate(stanza):
            if "adaptive" in v:
                adaptive = v.strip().lstrip("adaptive").strip()
            elif "cipherlist" in v:
                cipherlist = v.strip().lstrip("cipherlist").strip()
            elif "compatibility" in v:
                compatibility = v.strip().lstrip("compatibility").strip()
            elif "defaults-from" in v:
                defaults_from = v.strip().lstrip("defaults-from").strip()
            elif "destination" in v:
                destination = v.strip().lstrip("destination").strip()
            elif "interval" in v:
                interval = v.strip().lstrip("interval").strip()
            elif "ip-dscp" in v:
                ip_dscp = v.strip().lstrip("ip-dscp").strip()
            elif "recv-disable" in v:
                recv_disable = v.strip().lstrip("rscv-disable").strip()
            elif "recv" in v:
                recv = v.strip().lstrip("recv").strip()
            elif "send" in v:
                send = v.strip().lstrip("send").strip()
            elif "time-until-up" in v:
                time_until_up = v.strip().lstrip("time-until-up").strip()
            elif "timeout" in v:
                timeout = v.strip().lstrip("timeout").strip()

        cur.execute("INSERT INTO Monitors (Name, Type, Adaptive, Defaults_From, Destination, Interval, IP_DSCP, Recv, Recv_Disable, Send, Time_Until_Up, Timeout, Cipher_List, Compatibility) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (monitor, type, adaptive, defaults_from, destination, interval, ip_dscp, recv, recv_disable, send, time_until_up, timeout, cipherlist, compatibility));



    elif val.startswith("ltm profile"):
        p = val.removeprefix("ltm profile ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        plist = p.split(" ")
        profile = plist[1]
        type = plist[0]
        
        # Wipe variables... 
        app_service, cache_aging_rate, cache_client_cache_control_mode = "", "", ""
        cache_insert_age_header, cache_max_age, cache_max_entries = "", "", ""
        cache_object_min_size, cache_object_max_size, cache_size = "", "", ""
        cache_uri_exclude, cache_uri_include, cache_uri_include_override = "", "", ""
        cache_uri_pinned, cert, chain, cipher_group, ciphers = "", "", "", "", ""
        defaults_from, ecn, idle_timeout, inherit_certkeychain = "", "", "", ""
        key, metadata_cache_max_size, options, passphrase = "", "", "", ""
        port, proxy_buffer_low, proxy_buffer_high = "", "", ""
        receive_window_size, send_buffer_size = "", ""

        for i, v in enumerate(stanza):
            if "app-service" in v:
                app_service = v.strip().lstrip("app-service").strip()
            elif "cache-aging-rate" in v:
                cache_aging_rate = v.strip().lstrip("cache-aging-rate").strip()
            elif "cache-client-cache-control-mode" in v:
                cache_client_cache_control_mode = v.strip().lstrip("cache-client-cache-control-mode").strip()
            elif "cache-insert-age-header" in v:
                cache_insert_age_header = v.strip().lstrip("cache-insert-age-header").strip()
            elif "cache-max-age" in v:
                cache_max_age = v.strip().lstrip("cache-max-age").strip()
            elif "cache-max-entries" in v:
                cache_max_entries = v.strip().lstrip("cache-max-entries").strip()
            elif "cache-object-min-size" in v:
                cache_object_min_size = v.strip().lstrip("cache-object-min-size").strip()
            elif "cache-object-max-size" in v:
                cache_object_max_size = v.strip().lstrip("cache-object-max-size").strip()
            elif "cache-size" in v:
                cache_size = v.strip().lstrip("cache-size").strip()
            elif "cache-uri-exclude" in v:
                cache_uri_exclude = v.strip().lstrip("cache-uri-exclude").strip()
            elif "cache-uri-include-override" in v:
                cache_uri_include_override = v.strip().lstrip("cache-uri-include-override").strip()
            elif "cache-uri-pinned" in v:
                cache_uri_pinned = v.strip().lstrip("cache-uri-pinned").strip()
            elif "cert-key-chain" in v:
                continue
            elif "cert " in v:
                cert = v.strip().removeprefix("cert ")
            elif "cipher-group" in v:
                cipher_group = v.strip().lstrip("cipher-group").strip()
            elif "ciphers" in v:
                ciphers = v.strip().lstrip("ciphers").strip()
            elif "defaults-from" in v:
                defaults_from = v.strip().lstrip("defaults-from").strip()
            elif "ecn" in v:
                ecn = v.strip().lstrip("ecn").strip()
            elif "idle-timeout" in v:
                idle_timeout = v.strip().lstrip("idle-timeout").strip()
            elif "inherit-certkeychain" in v:
                inherit_certkeychain = v.strip().removeprefix("inherit-certkeychain ")
            elif "chain" in v:
                chain = v.strip().lstrip("chain").strip()
            elif "key" in v:
                key = v.strip().lstrip("key").strip()
            elif "metadata-cache-max-size" in v:
                metadata_cache_max_size = v.strip().lstrip("metadata-cache-max-size").strip()
            elif "options" in v:
                options = v.strip().removeprefix("options ")
            elif "passphrase" in v:
                passphrase = v.strip().lstrip("passphrase").strip()
            elif "port" in v:
                port = v.strip().lstrip("port").strip()
            elif "proxy-buffer-low" in v:
                proxy_buffer_low = v.strip().lstrip("proxy-buffer-low").strip()
            elif "proxy-buffer-high" in v:
                proxy_buffer_high = v.strip().lstrip("proxy-buffer-high").strip()
            elif "receive-window-size" in v:
                receive_window_size = v.strip().lstrip("receive-window-size").strip()
            elif "send-buffer-size" in v:
                send_buffer_size = v.strip().lstrip("send-buffer-size").strip()

        cur.execute("INSERT INTO Profiles (Name, Type, App_Service, Cache_Aging_Rate, Cache_Client_Cache_Control_Mode, Cache_Insert_Age_Header, Cache_Max_Age, Cache_Max_Entries, Cache_Object_Min_Size, Cache_Object_Max_Size, Cache_Size, Cache_Uri_Exclude, Cache_Uri_Include, Cache_Uri_Include_Override, Cache_Uri_Pinned, Cert, Chain, Cipher_Group, Ciphers, Defaults_From, ECN, Idle_Timeout, Inherit_CertKeyChain, Key, Metadata_Cache_Max_Size, Options, Passphrase, Port,Proxy_Buffer_Low, Proxy_Buffer_High, Receive_Window_Size, Send_Buffer_Size) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (profile, type, app_service, cache_aging_rate, cache_client_cache_control_mode, cache_insert_age_header, cache_max_age, cache_max_entries, cache_object_min_size, cache_object_max_size, cache_size, cache_uri_exclude, cache_uri_include, cache_uri_include_override, cache_uri_pinned, cert, chain, cipher_group, ciphers, defaults_from, ecn, idle_timeout, inherit_certkeychain, key, metadata_cache_max_size, options, passphrase, port, proxy_buffer_low, proxy_buffer_high, receive_window_size, send_buffer_size ));

    elif val.startswith("ltm persistence"):
        p = val.removeprefix("ltm persistence ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        stanza = lines[idx:end_idx]
        plist = p.split(" ")
        persistence = plist[1]
        type = plist[0]

        # Wipe variables...
        always_send, app_service, cookie_encryption, cookie_name = "", "", "", ""
        defaults_from, encrypt_cookie_poolname, expiration = "", "", ""
        hash_length, hash_offset, httponly, mask = "", "", "", ""
        match_across_pools, match_across_services, match_across_virtuals = "", "", ""
        method, mirror, override_connection_limit = "", "", ""
        secure, timeout = "", ""

        for i, v in enumerate(stanza):
            if "always-send" in v:
                always_send = v.strip().lstrip("always-send").strip()
            elif "app-service" in v:
                app_service = v.strip().lstrip("app-service").strip()
            elif "cookie-encryption-passphrase" in v:
                continue
            elif "cookie-encryption " in v:
                cookie_encryption = v.strip().lstrip("cookie-encryption").strip()
            elif "cookie-name" in v:
                coookie_name = v.strip().lstrip("cookie-name").strip()
            elif "defaults-from" in v:
                defaults_from = v.strip().lstrip("defaults-from").strip()
            elif "encrypt-cookie-poolname" in v:
                encrypt_cookie_poolname = v.strip().lstrip("encrypt-cookie-poolname").strip()
            elif "expiration" in v:
                expiration = v.strip().lstrip("expiration").strip()
            elif "hash-length" in v:
                hash_length = v.strip().lstrip("hash-length").strip()
            elif "hash-offset" in v:
                hash_offset = v.strip().lstrip("hash-offset").strip()
            elif "httponly" in v:
                httponly = v.strip().lstrip("httponly").strip()
            elif "mask" in v:
                mask = v.strip().lstrip("mask").strip()
            elif "match-across-pools" in v:
                match_across_pools = v.strip().lstrip("match-across-pools").strip()
            elif "match-across-services" in v:
                match_across_services = v.strip().lstrip("match-across-services").strip()
            elif "match-across-virtuals" in v:
                match_across_virtuals = v.strip().lstrip("match-across-virtuals").strip()
            elif "method" in v:
                method = v.strip().lstrip("method").strip()
            elif "mirror" in v:
                mirror = v.strip().lstrip("mirror").strip()
            elif "override-connection-limit" in v:
                override_connection_limit = v.strip().lstrip("override-connection-limit").strip()
            elif "secure" in v:
                secure = v.strip().lstrip("secure").strip()
            elif "timeout" in v:
                timeout = v.strip().lstrip("timeout").strip()

        cur.execute("INSERT INTO Persistence (Name, Type, Always_Send, App_Service, Cookie_Encryption, Cookie_name, Defaults_From, Encrypt_Cookie_Poolname, Expiration, Hash_Length, Hash_Offset, HTTP_Only, Mask, Match_Across_Pools, Match_Across_Services, Match_Across_Virtuals, Method, Mirror, Override_Connection_Limit, Secure, Timeout) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (persistence, type, always_send, app_service, cookie_encryption, cookie_name, defaults_from, encrypt_cookie_poolname, expiration, hash_length, hash_offset, httponly, mask, match_across_pools, match_across_services, match_across_virtuals, method, mirror, override_connection_limit, secure, timeout ));

    elif val.startswith("ltm rule"):
        #continue
        # Note - This doesn't really fit into sqlite or a CSV
         
        rule_name = val.removeprefix("ltm rule ").rstrip(" {")
        leading_spaces = len(val) - len(val.lstrip())
        end_idx = get_stanza_end(lines,idx,leading_spaces)
        rule = lines[idx+1:end_idx]
        rule_string = "\n".join(rule[1:])
        cur.execute("INSERT INTO Rules (Name, Rule) VALUES (?,?)", (rule_name,rule_string));
 
conn.commit()

# Write Tables to CSV
write_csv(conn,"SELECT * FROM Nodes","f5-nodes.csv")
write_csv(conn,"SELECT * FROM Pools","f5-pools.csv")
write_csv(conn,"SELECT * FROM VirtualAddresses","f5-virtualaddresses.csv")
write_csv(conn,"SELECT * FROM VirtualServers","f5-virtualservers.csv")
write_csv(conn,"SELECT * FROM Monitors","f5-monitors.csv")
write_csv(conn,"SELECT * FROM Profiles","f5-profiles.csv")
write_csv(conn,"SELECT * FROM Persistence","f5-persistence.csv")
write_csv(conn,"SELECT * FROM Rules","f5-rules.csv")
write_csv(conn,"SELECT VirtualServers.Name as 'VirtualServer', Pools.Name as 'Pool', Pools.Member_Name as 'Pool Member', Pools.Member_Address, VirtualServers.IP_Protocol as 'Protocol', VirtualServers.Profiles, VirtualServers.Rules, Pools.Monitor FROM Pools LEFT JOIN VirtualServers ON Pools.Name = VirtualServers.Pool","f5-overview.csv")

conn.close()

