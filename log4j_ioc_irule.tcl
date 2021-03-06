###
### Name   : log4j_ioc_irule
### Author : Niels van Sluis, (niels@van-sluis.nl)
### Version: 0.1
### Date   : 2021-12-26
###
when RULE_INIT {
    # set table timeout to 1 hour
    set static::log4j_ioc_timeout 3600
    set static::log4j_ioc_lifetime 3600
}

when CLIENT_ACCEPTED {
        set srcIPAddress [IP::remote_addr]
        set dstIPAddress [IP::local_addr]
        
        set key1 $srcIPAddress
        set key2 $dstIPAddress
        
        set verdict1 [table lookup -notouch $key1]
        set verdict2 [table lookup -notouch $key2]
        
        if { $verdict1 eq "" } {
            set rpc_handle [ILX::init log4j_ioc_plugin log4j_ioc_extension]
            if {[catch {ILX::call $rpc_handle checkIP $srcIPAddress} verdict1]} {
                log local0.error  "Client - [IP::client_addr], ILX failure: $verdict1"
                return
            }
            # cache verdict
            table set $key1 $verdict1 $static::log4j_ioc_timeout $static::log4j_ioc_lifetime
        }
            
        # verdict1 is malicous (reject) or benign (allow)
        if { $verdict1 eq "malicous" } {
            log local0. "rejected src $srcIPAddress to dst $dstIPAddress; $srcIPAddress is found on log4j blacklist"
            reject
            return
        }

        if { $verdict2 eq "" } {
            set rpc_handle [ILX::init log4j_ioc_plugin log4j_ioc_extension]
            if {[catch {ILX::call $rpc_handle checkIP $dstIPAddress} verdict2]} {
                log local0.error  "Client - [IP::client_addr], ILX failure: $verdict2"
                return
            }
            # cache verdict
            table set $key2 $verdict2 $static::log4j_ioc_timeout $static::log4j_ioc_lifetime
        }
        
        # verdict2 is malicous (reject) or benign (allow)
        if { $verdict2 eq "malicous" } {
            log local0. "rejected src $srcIPAddress to dst $dstIPAddress; $dstIPAddress is found on log4j blacklist"
            reject
            return
        }
}
