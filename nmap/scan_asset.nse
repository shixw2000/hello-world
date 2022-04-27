description = [[
    shixw nse
    2022-04-01

    usage: --script scan_asset --script-args \
        "patt_file=,out_file=,log_level=,mark=,dsp_body"
]]

author = "shixw"
license = "same"
categories = {"asset identifications"}
dependencies = {}

local stdnse = require("stdnse")
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit
local nmap = require "nmap"
local comm = require "comm"
local table = require "table"
local tableaux = require "tableaux"
local shortport = require"shortport"
local sslcert = require "sslcert"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")
local datetime = require "datetime"
local oops = require "oops"
local io = require "io"
local os = require "os"
local http = require "http"


--global
local g_scan_key = "global_scan_assets";
local g_seq_asset_key = "global_asset_by_seq";
local g_level_asset_key = "global_asset_by_level";
local g_url_key = "global_probe_url";
local g_hosts_key = "global_probe_hosts";

--by host
local host_sec_name = "host_section";

local cur_level_key = "probe_host_level";
local cur_info_key = "probe_host_info"; 

local cur_result_key = "probe_url_result";

local host_probe_finish_key = "probe_host_status";

local DEF_LEVEL = 100;


local arg_pattern_file = stdnse.get_script_args('patt_file') or "/usr/private/pattern_device_dec";
local arg_out_file = stdnse.get_script_args('out_file') or "/tmp/scan/scan_ret";
local arg_mark = stdnse.get_script_args('mark');
local arg_dsp_body = stdnse.get_script_args('dsp_body');
local arg_log_level = stdnse.get_script_args('log_level');


--1:info, 2:debug, 3:verbose
local LOG_INFO,LOG_DEBUG,LOG_VERBOSE=1,2,3

local cur_log_level = arg_log_level and tonumber(arg_log_level) or 1;

local function log_print(level, ...)
    if (level <= cur_log_level) then
        print(...);
    end
end

function log_info(...) return log_print(1, ...) end
function log_debug(...) return log_print(2, ...) end
function log_verbose(...) return log_print(3, ...) end


local function get_host_cache(host, sec_name, key)
    if (host.registry.sec_name) then
        local tbl = host.registry.sec_name;
        
        return tbl[key];
    else
        return nil; 
    end
end

local function set_host_cache(host, sec_name, key, val)
    host.registry.sec_name = host.registry.sec_name or {}

    local tbl = host.registry.sec_name;

    tbl[key] = val;
end

local function get_global_table(tbl_name)
    if (type(tbl_name) == "string") then
        return stdnse.registry_get({g_scan_key, tbl_name});
    else
        return nil;
    end
end

local function set_global_table(tbl_name, val)
    stdnse.registry_add_table({g_scan_key}, tbl_name, val, true);
end

local function get_global_key(tbl_name, sec_name, key)
    return stdnse.registry_get({g_scan_key, tbl_name, sec_name, key});
end

local function set_global_key(tbl_name, sec_name, key, val)
    stdnse.registry_add_table({g_scan_key, tbl_name, sec_name}, key, val, true);
end

local function trim(text)
    return string.gsub(text, '^[%s]*(.-)[%s]*$', "%1");
end

local function strsplit_trim(pattern, text)
    if (not pattern or not text) then
        return {};
    end
    
    local arr_str = strsplit(pattern, text); 
    local list = {}
    
    if ("table" == type(arr_str)) then
        for _, v in ipairs(arr_str) do
            list[_] = trim(v);
        end
    end

    return list;
end

prerule = function()
    return true;
end

postrule = function()
    return true;
end


hostrule = function(host)
    return true;
end


portrule = function(host, port)
    if (port.protocol == "tcp" and port.state == "open") then

        log_debug("****port=" .. port.number 
            .. "| dtype=" .. port.version.service_dtype 
            .. "| service=" .. (port.version.name or "unknwon")
            .. "| ssl=" .. (port.version.service_tunnel or 'none'));
        
        --not finish yet
        if (not get_host_cache(host, host_sec_name, host_probe_finish_key)) then    
            
            if ( (port.version.service_dtype == "probed" 
                    and port.version.name == "http")
                or (port.version.service_tunnel == "ssl") ) then
                return true;
            end
        end
    end
end


local function md5_string(msg)
    local md5;
    
    if (msg) then
        md5 = stdnse.tohex(openssl.md5(msg));
    else
        md5 = "NIL";
    end
    
    return md5;
end


dsp_tbl = function(tbl, log_level, indent) 
    log_print(log_level, "----disp_tbl---");
    
    if (type(tbl) == "table") then 
        indent = indent or "";
        log_level = log_level or LOG_VERBOSE
        
        for k,v in pairs(tbl) do 

            if type(v) ~= "table" then   
                log_print(log_level, indent .. "key="..k.."| val=" .. tostring(v) .. "|");  
            else   
                log_print(log_level, indent .. "key="..k.."| val_tbl:");  
                
                indent1 = "  " .. indent;   
                dsp_tbl(v, log_level, indent1); 
            end 
        end
    end
end

local function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, 
        unicode.utf16_dec, unicode.utf8_enc,
        false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, 
        unicode.utf16_dec, unicode.utf8_enc, 
        true, nil)
  else
    return str
  end
end

local NON_VERBOSE_FIELDS = { 
    "commonName", 
    "organizationName", 
    "stateOrProvinceName", 
    "countryName" 
}

function stringify_name(name)
    local fields = {}
    local _, k, v
    
    if not name then
        return nil
    end
  
    for _, k in ipairs(NON_VERBOSE_FIELDS) do
        v = name[k]
        if v then
            fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
        end
    end
  
    for k, v in pairs(name) do
        -- Don't include a field twice.
        if not tableaux.contains(NON_VERBOSE_FIELDS, k, true) then
            if type(k) == "table" then
                k = table.concat(k, ".")
            end
            
            fields[#fields + 1] = string.format("%s=%s", 
                k, maybe_decode(v) or '')
        end
    end

    return table.concat(fields, "/")
end

function dsp_cert(cert)  
    log_debug("Subject: " .. stringify_name(cert.subject));
    log_debug("Issuer: " .. stringify_name(cert.issuer)); 
    log_debug("Not Before: " .. date_to_string(cert.validity.notBefore));
    log_debug("Not after: " .. date_to_string(cert.validity.notAfter));
    log_debug("MD5: " .. stdnse.tohex(cert:digest("md5")));
end 

local function initItem(item)
    if (nil == item) then
        --init item;
        item = {};
        return true, item;
    else 
        return false, oops.err("initItem: invalid item");
    end
end

local function parseItem(item, line)
    if (type(item) ~= "table" or type(line) ~= "string") then 
        return false, oops.err(
            ("parseItem: invalid item(%s) or line(%s)"):format(
            type(item), type(line)));
    end
    
    local key,val = line:match("^%s*([%w_]+)%s*=%s*(.-)%s*$");
    if (key and val) then
        log_verbose("**********key=" .. key .. "| val=" .. val .. "|");
        
        if (not item[key]) then
            item[key] = val;
            return true, item;
        else
            return false, oops.err(("parseItem: duplicate key(%s)"):format(key));
        end
    else
        return false, oops.err(("parseItem: invalid line(%s)"):format(line));
    end
end

local function is_num(v)
    if (type(v) == "string" and string.match(v, "^%d+$")) then
        return true;
    else
        return false;
    end
end

local function chkItem(item)
    
    if (type(item) ~= "table") then 
        return false, oops.err("chkItem: invalid input"); 
    end

    if (not is_num(item['mark'])) then
        return false, oops.err("chkItem: invalid mark");
    end

    if (not is_num(item['level'])) then
        return false, oops.err("chkItem: invalid level");
    end

    if (not is_num(item['group_id'])) then
        return false, oops.err("chkItem: invalid group_id");
    end

    return true;
end

local function need_ignore(item)
    if (not item) then
        return true;
    end
    
    if (item.inuse and "1" == item.inuse) then 
        return true;
    end
    
    if (arg_mark and arg_mark ~= item['mark']) then
        return true;
    end

    return false;
end

local function addItem(asset, level_asset, item)
    if (need_ignore(item)) then
        return true;
    end
    
    local status, ret = chkItem(item);

    if (not status) then 
        return status, ret; 
    end 
    
    asset[#asset+1] = item;

    local seqno = #asset;

    level_asset[seqno] = {
        seqno = seqno,
        
        mark = tonumber(item['mark']), 
        group_id = tonumber(item['group_id']),
        level = tonumber(item['level']),

        url = item['url'],
        url_keyword = item['url_keyword'],

        os_class_confirm = item['os_class_confirm'],
    }

    return true;
end

function parse_pattern(filename, asset, level_asset)
    local status, ret, file;
    local total, item, has_complete;
    local lineno, lastline;
    
    if (not filename or type(filename) ~= "string" or filename == "") then
        return false, oops.err(
            ("parse_pattern: filename(%s) invalid"):format(tostring(filename)));
    end

    local filepath = nmap.fetchfile(filename) or filename;
    
    file, ret, _ = io.open( filepath, "rb" )
    if not file then
        return false, oops.err(
            ("Cannot open %s for reading: %s"):format(filepath, ret));
    end

    lineno = 0; 
    total = 0; 
    asset = asset or {}
    level_asset = level_asset or {}

    --init state
    status = false;
    ret = "empty file";
    has_complete = false;
    item = nil;
    
    for line in file:lines() do
        lineno = lineno + 1;
        lastline = line;
        
        -- comment line or empty line
        if (line:find("^#") or line:find("^%s*$")) then 
            --do nothing; 
        elseif (line:match("^begin%s*$")) then
            status, ret = initItem(item);

            if (status) then
                item = ret;
                has_complete = false;
            else
                break;
            end
            
        elseif (line:match("^end%s*$")) then 
            status, ret = addItem(asset, level_asset, item);
            if (status) then
                total = total + 1;
                
                item = nil;
                has_complete = true;
            else
                break;
            end
            
        else
            status, ret = parseItem(item, line);
            if (status) then
                item = ret;
            else
                break;
            end
            
        end
    end

    file:close()

    if (status) then
        if (has_complete) then
            return true, asset, level_asset;
        else
            return false, oops.err(
                ("parse file(%s) incompleted: cnt=%d, lineno=[%d:%s]"):format(
                filepath, total, lineno, lastline));
        end
    else
        return false, oops.err(
            ("parse file(%s) error: cnt=%d, lineno=[%d:%s]"):format(
            filepath, total, lineno, lastline),
            ret);
    end
end

local function cmp_level(a, b) 
    if (a.level < b.level or (a.level == b.level and a.mark < b.mark)) then
        return true;
    else
        return false;
    end
end

local function cmp_score(a, b)
    return a.score > b.score or (a.score == b.score and a.url < b.url)
end

local function analyse_os_patt(item)
    local list = nil;
    
    if (item.os_class_confirm and "" ~= item.os_class_confirm) then
        local i, j = string.find(item.os_class_confirm, "%*%*");
        
        if (not i) then
            local arr_os = strsplit_trim("|", item.os_class_confirm);
            
            if (#arr_os == 4 and "" ~= arr_os[1] and "" ~= arr_os[4]) then
                list = {
                    vendor = arr_os[1], 
                    osfamily = arr_os[2], 
                    osgen = arr_os[3], 
                    type = arr_os[4]
                }
            end
        else
            list = {
                vendor = trim(string.sub(item.os_class_confirm, 1, i-1)), 
                osfamily = "", 
                osgen = "", 
                type = trim(string.sub(item.os_class_confirm, j+1))
            }
        end
    end
    
    item['os_rules'] = list;
    return true;
end

local function analyse_url(item)
    local status, path;
    
    if (item.url) then
        path = item.url;
    else
        path = "";
    end

    if (item.url_keyword and "" ~= item.url_keyword) then
        local arr_url = strsplit_trim("|", path);
        local arr_patt = strsplit_trim("|", item.url_keyword);

        if (#arr_url ~= #arr_patt) then
            return false, oops.err(
                ("analyse_url err: url=%s| url_keyword=%s|"):format(
                    item.url, item.url_keyword));
        end

        local arr_rule = {};
        local patt, method, e;
        
        for i, url in ipairs(arr_url) do
            if (not string.match(url, "^/")) then
                url = "/" .. url;
            end
            
            patt = arr_patt[i]; 

            if (string.match(patt, "^MD5:(.*)$")) then
                e = string.match(patt, "^MD5:(.*)$");
                
                method = "md5"; 
                val = strsplit_trim(',', e);
            elseif (string.match(patt, "^CMODEL:(.*)$")) then
                e = string.match(patt, "^CMODEL:(.*)$");
                
                method = "cmodel"; 
                val = {e};
            elseif (string.match(patt, "^MODEL:(.*)$")) then
                e = string.match(patt, "^MODEL:(.*)$");
                
                method = "model"; 
                val = {e};
            else
                method = "expr";
                --patt is whole words

                val = {patt};
            end 
            
            arr_rule[#arr_rule+1] = {
                url = url,
                rule = method,
                pattern = val
            };
        end

        item['url_rules'] = arr_rule;
    end
        
    return true;
end

local function chk_os_rule(host, level_item, probe_result)

    if (not host.os or not level_item or not level_item['os_rules']) then
        return false;
    end
    
    dsp_tbl(host.os, LOG_VERBOSE);
    dsp_tbl(level_item['os_rules'], LOG_VERBOSE);

    for _1, os_item in ipairs(host.os) do
        
        for _2, cls_item in ipairs(os_item.classes) do
            local matched = true;
            
            for k, v in pairs(level_item['os_rules']) do
                log_debug( ("os_name=%s| k=%s| val=%s| chk_val=%s|"):format(
                    os_item.name, k, cls_item[k], v) );
                    
                if ("" ~= v and cls_item[k] ~= v) then
                    matched = false;
                    break;
                end
            end

            if (matched) then
                local res = {};
                
                res['os_name'] = os_item.name;
                res['vendor'] = cls_item['vendor'];
                res['osfamily'] = cls_item['osfamily'];
                res['osgen'] = cls_item['osgen'];
                res['type'] = cls_item['type'];
                res['cpe'] = cls_item['cpe'];

                return true, {test_os = res};
            end
        end
    end
    
    return false;
end

local chk_url_rules = {
    --reg expr
    expr = function(url, response, pattern)
        if (not response['body'] or not pattern) then
            return false;
        end

        for _, patt in ipairs(pattern) do
            if ("" ~= patt) then
                if(string.find(response['body'], patt)) then
                    return true, patt;
                end
            end
        end

        return false;
    end,

    --md5 match
    md5 = function(url, response, pattern)
        if (not response['body'] or not pattern) then
            return false;
        end

        if (not response.body_md5) then
            response.body_md5 = md5_string(response.body);
        end

        for _, patt in ipairs(pattern) do
            if ("" ~= patt and patt == response.body_md5) then
                return true, patt;
            end
        end

        return false; 
    end,

    --cmodel match
    cmodel = function(url, response, pattern)
        if (not response['body'] or not pattern) then
            return false;
        end

        for _, patt in ipairs(pattern) do
            if ("" ~= patt) then
                local m = {string.match(response['body'], patt)};

                if(m and #m > 0) then
                    return true, m[1];
                end
            end
        end

        return false;
    end,

    --model match
    modle = function(url, response, pattern)
        return cmodel(url, response, pattern);
    end,
}

--return status, match_res
local function chk_url(host, port, url, response, level_item, result)
    if (not url or not response['body'] or not level_item['url_rules']) then
        return false;
    end

    local has_ok, has_mismatch;
    local status, patt, method, rule;
    local seqno = level_item['seqno'];
    local url_rules = level_item['url_rules'];

    --check if all conditions matched
    has_ok = false;
    has_mismatch = false;
    
    for i, item in ipairs(url_rules) do
        method = item['rule'];
        
        if (url == item['url'] and chk_url_rules[method]) then
            rule = chk_url_rules[method];
            
            status, patt = rule(url, response, item.pattern);

            if (status) then 
                has_ok = true;
                
                if (not result[seqno]) then
                    result[seqno] = {};
                end

                result[seqno][i] = {
                    port = (type(port) == "table") and port.number or port;
                    url = url;
                    method = method;
                    result = patt;
                }
            else
                --if one dismatch, then return not all matched
                has_mismatch = true;
            end
        else
            --model is optional condition
            if (method ~= "model" and (not result[seqno] 
                or not result[seqno][i])) then
                
                --has no-matched conditions
                has_mismatch = true;
            end
        end
    end

    --here all conditions are matched
    if (has_ok and not has_mismatch) then
        return true, {test_url = result[seqno]};
    else
        return false;
    end
end

--return status, item, result
local function detect_url_asset(host, port, path, response, 
    level_asset, cur_level, result)
    local status, res;
    
    for _, level_item in ipairs(level_asset) do
    
        --check level
        if (cur_level > level_item.level) then 
            status, res = chk_url(host, port, path, response, level_item, result);
            
            if (status) then 
                return status, level_item, res;
            end
        else
            break;
        end
    end

    return false;
end

local function prepare_data(asset, level_asset)
    if ("table" ~= type(asset) or "table" ~= type(level_asset)) then 
        return false, oops.err("prepare_data: invalid input"); 
    end

    local arr_url = {};
    local url_hits = {};
    
    for _, item in ipairs(level_asset) do
        local status, ret = analyse_url(item);

        if (not status) then
            return false, ret;
        end

        analyse_os_patt(item);
        
        if (item['url_rules']) then
            for __, key in ipairs(item['url_rules']) do
                if (not url_hits[key.url]) then
                    url_hits[key.url] = 1;
                else
                    url_hits[key.url] = url_hits[key.url] + 1;
                end
            end
        end
    end

    for k, v in pairs(url_hits) do
        table.insert(arr_url, {url=k, score=v});
    end

    if (#arr_url > 0) then
        table.sort(arr_url, cmp_score);
    else
        log_info("****prepare_data: url count is 0"); 
    end 

    --sort level asset
    table.sort(level_asset, cmp_level);

    dsp_tbl(asset, LOG_DEBUG);
    dsp_tbl(level_asset, LOG_DEBUG);
    dsp_tbl(arr_url, LOG_DEBUG);

    set_global_table(g_seq_asset_key, asset);
    set_global_table(g_level_asset_key, level_asset);
    set_global_table(g_url_key, arr_url);
    set_global_table(g_hosts_key, {});

    return true;
end


function getHttpInfo(host, port, is_ssl, path)
    local status, response;
    local option = {
        scheme = (is_ssl == 1 and "https" or "http"),
        timeout = 2000,

        redirect_ok = 1,
        max_body_size = 10 * 1024 * 1024,
        truncated_ok = true,

        header = {
            ["User-Agent"] = "Wget/1.12 (linux-gnu)",
            ["Accept"] = "*/*",
        }
    };
  
    response = http.get(host.ip, port.number, path, option);
    
    if (tostring(response.status):match("^[123]%d%d$")) then
        --ok
        status = true;

        dsp_tbl(response.rawheader, LOG_VERBOSE);
        
        log_debug(("********host=%s| port=%d| is_ssl=%d| path=%s| status_line=%s|"
            .. " ok_body=%d:%s|"):format(
            host.ip, port.number, is_ssl, path, response['status-line'],
            #response.body,
            arg_dsp_body and response.body or md5_string(response.body)));
    else
        status = false;

        dsp_tbl(response.rawheader, LOG_VERBOSE);
        
        log_debug(("********host=%s| port=%d| is_ssl=%d| path=%s| status_line=%s|"
            .. " err_body=%s|"):format(
            host.ip, port.number, is_ssl, path, response['status-line'], 
            arg_dsp_body and response.body or md5_string(response.body)));
    end
    
    return status, response;
end

function preaction()
    local status, ret, asset, level_asset;

    status, asset, level_asset = parse_pattern(arg_pattern_file, asset, level_asset);
    if (status) then 

        status, ret = prepare_data(asset, level_asset);
        if (status) then
            log_info("*********preaction ok|"); 
        else
            log_info("*********preaction error| status=|" .. tostring(ret));
            os.exit(9);
        end
    else
        log_info("*********preaction error| status=" .. tostring(asset));
        os.exit(9);
    end
end

local function write_result(ip, asset, level_item, res)
    local status, filename, f;
    local seqno;
    local asset_info;
    local ctx;

    if (level_item) then
        seqno = level_item.seqno;
        asset_info = asset[seqno] or {}
        ctx = ("level-%d:%d&%d&%s&%s"):format(
            level_item.level,
            level_item.group_id,
            level_item.mark,
            asset_info.os_type or "",
            asset_info.model or "");
    else
        ctx = "level-4:8&0";
    end

    filename = arg_out_file .. "-" .. ip;
    
    f, status = io.open(filename, "wb")
    if not f then
        log_info(("Cannot open(%s) for writing: %s"):format(filename, status));
        return false;
    end

    f:write(ctx);
    f:flush();
	f:close();

	return true;
end

function postaction()
    local all_hosts = get_global_table(g_hosts_key);
    local asset = get_global_table(g_seq_asset_key);

    if (not all_hosts) then
        log_info("********postaction| there is no host|");
        return;
    else
        log_info("********postaction| list hosts:");
    end
    
    for host_name, host_info in pairs(all_hosts) do
        if (host_info[cur_info_key]) then
            local item = host_info[cur_info_key];
            local res = host_info[cur_result_key];
            
            log_info(("*****postaction ok| match_host=%s| level=%d|"
                .." mark=%d| group_id=%d| result_list:"):format(
                host_name, item.level, 
                item.mark, item.group_id));

            dsp_tbl(res, LOG_INFO);

            write_result(host_name, asset, item, res);
        else
            log_info(("*****postaction unknown| no_match_host=%s|"):format(
                host_name));

            write_result(host_name, asset, nil, nil);
        end
    end
  
end

--return has_found, found_item
local function detectHostOs(host, cur_level, probe_result)
    local status, res, has_found, found_item;
    local host_name = stdnse.get_hostname(host);

    --from global
    local level_asset = get_global_table(g_level_asset_key);

    for _, level_item in ipairs(level_asset) do
    
        --check level
        if (cur_level > level_item.level) then 
            status, res = chk_os_rule(host, level_item, probe_result);
            
            if (status) then 
                has_found = true;
                found_item = level_item;

                log_debug(("*********match os ok item| mark=%d| level=%d:%d|"):format(
                    level_item.mark, level_item.level, cur_level)); 

                --set global val if matched every time
                set_global_key(g_hosts_key, host_name, cur_level_key, level_item.level);
                set_global_key(g_hosts_key, host_name, cur_info_key, level_item);
                set_global_key(g_hosts_key, host_name, cur_result_key, res);

                --update level
                cur_level = level_item.level;

                --set local host val
                set_host_cache(host, host_sec_name, cur_level_key, cur_level);

                --notify exit for this host
                if (cur_level <= 1) then
                    set_host_cache(host, host_sec_name, host_probe_finish_key, true);
                    break;
                end
            end
        else
            break;
        end
    end

    return has_found, found_item;
end


function hostaction(host)
	local host_name = stdnse.get_hostname(host);
	
	if (not get_global_key(g_hosts_key, host_name, cur_level_key)) then
        set_global_key(g_hosts_key, host_name, cur_level_key, DEF_LEVEL);
	end

	if (not host.os) then
	    return;
    end

    local cur_level = get_host_cache(host, host_sec_name,
            cur_level_key) or DEF_LEVEL;
    local probe_result = {};

    local has_found, found_item = detectHostOs(host, cur_level, probe_result);
    if (has_found) then
        log_debug(("*****detect host_os ok| host=%s|"
            .. " level=%d| mark=%d|"):format(
            host.ip, found_item.level, found_item.mark));
    end
end

--return has_found, found_item
function detectAsset(host, port, is_ssl, cur_level, probe_result)
    local has_found, found_item;
    local status, response, level_item, res;
    local host_name = stdnse.get_hostname(host);

    --from global
    local level_asset = get_global_table(g_level_asset_key);
    local arr_url = get_global_table(g_url_key);
    
    for _, v in ipairs(arr_url) do
        status, response = getHttpInfo(host, port, is_ssl, v.url);
        if (status) then
            status, level_item, res = detect_url_asset(host, port, 
                v.url, response, level_asset, cur_level, probe_result);
            if (status) then
                has_found = true;
                found_item = level_item;
                
                log_debug(("*********match ok item| url=%s| mark=%d| level=%d:%d|"):format(
                    v.url, level_item.mark, level_item.level, cur_level)); 

                dsp_tbl(res, LOG_DEBUG);

                --set global val if matched every time
                set_global_key(g_hosts_key, host_name, cur_level_key, level_item.level);
                set_global_key(g_hosts_key, host_name, cur_info_key, level_item);
                set_global_key(g_hosts_key, host_name, cur_result_key, res);

                --update level
                cur_level = level_item.level;

                --set local host val
                set_host_cache(host, host_sec_name, cur_level_key, cur_level);

                --notify exit for this host
                if (cur_level <= 1) then
                    set_host_cache(host, host_sec_name, host_probe_finish_key, true);
                    break;
                end
            end
        end
    end

    return has_found, found_item;
end

function portaction(host, port) 
    local is_ssl = 0; 
    local has_found, found_item;

    dsp_tbl(port, LOG_DEBUG); 
    
    if (port.version.service_tunnel == "ssl") then
        is_ssl = 1;
        
        local status, cert = sslcert.getCertificate(host, port);
        
        if (status) then 
            dsp_cert(cert); 
        else
            log_info("getCertificate error: ", cert or "unknown")
        end 
    end

    --http or https
    if (port.version.service_dtype == "probed" 
        and port.version.name == "http") then
        
        --init host variables for each port
        local cur_level = get_host_cache(host, host_sec_name,
            cur_level_key) or DEF_LEVEL;
        local probe_result = {};
           
        has_found, found_item = detectAsset(host, port, is_ssl, 
            cur_level, probe_result);
        if (has_found) then
            log_debug(("*****detect asset ok| host=%s| port=%d| is_ssl=%d|"
                .. " level=%d| mark=%d|"):format(
                host.ip, port.number,
                is_ssl, found_item.level, found_item.mark));
        end
    else
        --just ssl
    end
end

local actios = { 
    prerule = preaction, 
    hostrule = hostaction, 
    portrule = portaction, 
    postrule = postaction
}

action = function(...) 
    return actios[SCRIPT_TYPE](...)
end

