local stdnse = require "stdnse"
local shortport = require "shortport"
local datafiles = require "datafiles"
local datafiles = require "string"
local stringaux = require "stringaux"
local table = require "table"
local tableaux = require "tableaux"
local nmap = require "nmap"
local comm = require "comm"
local lpeg = require "lpeg"
local U = require "lpeg-utility"
local io = require "io"
local http = require "http"
local httpspider = require "httpspider"
local os = require "os"
local sslcert = require "sslcert"
local outlib = require "outlib"
local debug = require "debug"
local openssl = stdnse.silent_require "openssl"
local have_openssl, openssl = pcall(require, "openssl")
local rtsp = require "rtsp"

categories = {"auth"}


dsp_tbl = function(tbl, indent) 
    print("----disp_tbl---");   
    if (type(tbl) == "table") then    
        indent = indent or "";         
        
        for k,v in pairs(tbl) do       
            if type(v) ~= "table" then        
                print(indent .. "key="..k.."| val=" .. tostring(v) .. "|");       
            else               
                print(indent .. "key="..k.."| val_tbl:");               
                indent1 = "  " .. indent;         
                dsp_tbl(v, indent1);      
            end       
        end  
    end
end 

function test_port()
 local host = "172.16.5.254";	
 local port = 443;	
 local path = '/simple/view/login.html';	
 local is_ssl = 1;
 local state, response;
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

 response = http.get(host, port, path, option);
 if (response.status) then	 
    print( ("---------------yes: status_line=%s|"
            .. " ok_body=%s|"):format(
			response['status-line'],
            response.body) );	
 else	 
    print( ("---------------no: status_line=%s|"):format(
	 response['status-line']) );
 end		

 --dsp_tbl(response);
end

function test_host(host)
dsp_tbl(host);
end

hostrule=function(host)
 return true;
end

action = function(...)
 test_host(...);
end

