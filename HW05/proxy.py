# Original Source by Luu Gia Thuy (https://github.com/luugiathuy/WebProxyPython/)

import os, sys, socket, json;
import _thread as thread;

### Constant Values
BACKLOG = 50;
MAX_DATA_RECV = 999999;
IN_BOUND = 0;
OUT_BOUND = 1;

### Option Values
DEBUG = True;
BLOCKED = [];
FILTER = [];
CACHELIST = [];
ENCODING = "UTF-8"

### Cached Values
CACHED = {};

def web_proxy(ip, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
		s.bind((ip, port));
		s.listen(BACKLOG);

	except socket.error as message:
		if s: s.close();
		print("ERROR: Could not open socket! - {}".format(message));
		sys.exit(1)

	print("Capturing Packets...");
	while True:
		(conn, client_addr) = s.accept();
		try:
			thread.start_new_thread(proxy_thread, (conn, client_addr));
		except:
			print("ERROR: The mysterious error!");

	s.close();

def printout(typ, request, address):
	if "Block" in typ or "Blacklist" in typ: colornum = 91; #red
	elif "Request" in typ: colornum = 92;
	elif "Reset" in typ: colornum = 93;
	elif "Cached" in typ: colornum = 94; #blue

	print("\033[{}m{}\t{}\t{}\033[0m".format(colornum, address[0], typ, request));

def change_bytes(pkt):
	if len(FILTER) == 0: return pkt;
	for rule in FILTER:
		pkt = pkt.replace(bytes(rule['from'], ENCODING), bytes(rule['to'], ENCODING));
	return pkt;

def change_packet_http(pkt, typ, chunked=False):
	if len(FILTER) == 0: return pkt;
	
	if typ == IN_BOUND:
		if chunked:
			st = 0;
			if pkt.find(b'Transfer-Encoding: chunked') != -1: st = pkt.find(b'\r\n\r\n');
			pkt_fir = pkt[:st];
			pkt_sec = pkt[st:];
			print(pkt_sec);

			(pv, ix, cnt, mode, content) = (0, 0, 0, 1, b'');
			while ix < len(pkt_sec):
				if pkt_sec[ix:ix+2] == b'\r\n':
					if mode == 1: pkt_fir += b'\r\n';
					ix += 2;
					continue;
				if mode == 1:
					tmp = pkt_sec[ix:].find(b'\r\n');
					if tmp < 0:
						print("Wrong HTTP Packet");
						return (pkt, b''); # In Case of Error

					cnt = int(pkt_sec[ix:ix+tmp].decode("UTF-8", "replace"), 16);
					mode = 0;
					ix += tmp+2;
					continue;

				if cnt==0:
					pkt_fir += b'0\r\n\r\n';
					pv = len(pkt_sec);
					break;

				content = content + pkt_sec[ix:ix+1];
				(ix, cnt) = (ix+1, cnt-1);
				if cnt == 0:
					content = change_bytes(content);
					pkt_fir += bytes(format(len(content), 'X'), "UTF-8");
					pkt_fir += b'\r\n';
					pkt_fir += content;
					pkt_fir += b'\r\n';
					pv = ix;
					mode = 1;
					content = b'';

			pkt_sec = pkt_sec[pv:];
			return (pkt_fir, pkt_sec);
		else:
			st = pkt.find(b'Content-Length:');
			en = st + pkt[st+1:].find(b'\r\n');
			data_st = pkt.find(b'\r\n\r\n');
			if st < 0 or en < 0 or en >= data_st:
				print("Wrong HTTP Packet");
				return pkt;
			
			pkt_chg = change_bytes(pkt[data_st:]);
			pkt_chg = bytes(str(len(pkt_chg)), "UTF_8") + b'\r\n' + pkt[en:data_st] + pkt_chg;
			return pkt[:st] + pkt_chg;

	elif typ == OUT_BOUND:
		pkt = pkt.replace(b'gzip, ', b'');
		pkt = pkt.replace(b'gzip', b'');

	return pkt;

def change_packet_https(pkt, typ, chunked=False):
	return pkt;

def proxy_thread(conn, client_addr):
	request = conn.recv(MAX_DATA_RECV);

	first_line = request.decode("UTF-8", "replace").split('\n')[0];
	if first_line.find(' ') == -1:
		conn.close();
		return;

	url = first_line.split(' ')[1];

	for black in BLOCKED:
		if black in url:
			printout("Blacklisted", first_line, client_addr);
			conn.close();
			return;

	if url in CACHED:
		printout("Cached", first_line, client_addr);
		conn.send(CACHED[url]);
		conn.close();
		return;

	http_pos = url.find("://");
	if http_pos==-1: temp = url;
	else: temp = url[(http_pos+3):];

	port_pos = temp.find(":");

	webserver_pos = temp.find("/");
	if webserver_pos == -1: webserver_pos = len(temp);

	is_image = False;
	if webserver_pos != len(temp):
		temp_back = temp[webserver_pos:];
		for ext in CACHELIST:
			if url.find(ext)!=-1: is_image = True;
	if not is_image: request = change_packet_http(request, OUT_BOUND); # image file should be gzipped
	
	webserver = "";
	port = -1;
	if port_pos == -1 or webserver_pos < port_pos:
		if url[0:5] == 'https': port = 443;
		else: port = 80;
		webserver = temp[:webserver_pos];
	else:
		port = int(temp[port_pos+1:webserver_pos]);
		webserver = temp[:port_pos];
	
#	print("PACKET: ");
#	print(request.decode("UTF-8", "replace"));
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((webserver, port));
		s.send(request);

		(chunked, succeed) = (False, False);
		merged = b'';
		while True:
			data = s.recv(MAX_DATA_RECV)
			if len(data) > 0:
				if data.find(b'Transfer-Encoding: chunked') != -1: chunked = True;
				if data.find(b'200 OK') != -1: succeed = True;
				if port==80 and succeed and not is_image:
					if chunked: (data, merged) = change_packet_http(merged+data, IN_BOUND, True);
					else: data = change_packet_http(data, IN_BOUND);
				if is_image: merged += data;
				else: conn.send(data);
			else: break;
	
		if is_image and merged.find(b'200 OK')!=-1:
			CACHED[url] = merged;
			conn.send(merged);
			
		s.close();
		conn.close();
	
	except socket.error as message:
		print(message);
		if s: s.close();
		if conn: conn.close();
		printout("Peer Reset", first_line, client_addr);
		sys.exit(1);

if __name__ == "__main__":
	json_data = open("config.json").read();
	data = json.loads(json_data);
	
	if "blacklist" in data: BLOCKED = data["blacklist"];
	if "replaceWord" in data: FILTER = data["replaceWord"];
	if "cacheList" in data: CACHELIST = data["cacheList"];
	if "encoding" in data: ENCODING = data["encoding"];

	try:
		ip = data["ip"];
		port = data["port"];
		web_proxy(ip, port);
	except KeyError as message:
		print("ERROR : config.json file is wrong!");
	except KeyboardInterrupt:
		print("Proxy Server is closed!");
