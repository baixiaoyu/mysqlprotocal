package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	CLIENT_LONG_PASSWORD uint32 = 1 << iota
	CLIENT_FOUND_ROWS
	CLIENT_LONG_FLAG
	CLIENT_CONNECT_WITH_DB
	CLIENT_NO_SCHEMA
	CLIENT_COMPRESS
	CLIENT_ODBC
	CLIENT_LOCAL_FILES
	CLIENT_IGNORE_SPACE
	CLIENT_PROTOCOL_41
	CLIENT_INTERACTIVE
	CLIENT_SSL
	CLIENT_IGNORE_SIGPIPE
	CLIENT_TRANSACTIONS
	CLIENT_RESERVED
	CLIENT_SECURE_CONNECTION
	CLIENT_MULTI_STATEMENTS
	CLIENT_MULTI_RESULTS
	CLIENT_PS_MULTI_RESULTS
	CLIENT_PLUGIN_AUTH
	CLIENT_CONNECT_ATTRS
	CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
)

const (
	OK_HEADER          byte = 0x00
	ERR_HEADER         byte = 0xff
	EOF_HEADER         byte = 0xfe
	LocalInFile_HEADER byte = 0xfb
)

func CalcPassword(scramble, password []byte) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA1(password)
	crypt := sha1.New()
	crypt.Write(password)
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA1(scramble + SHA1(stage1Hash))
	// inner Hash
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)

	// outer Hash
	crypt.Reset()
	crypt.Write(scramble)
	crypt.Write(hash)
	scramble = crypt.Sum(nil)

	// token = scrambleHash XOR stage1Hash
	for i := range scramble {
		scramble[i] ^= stage1[i]
	}
	return scramble
}

func getConnection(protocal string, addr string) net.Conn {
	// 开始dial下地址
	conn, err := net.Dial(protocal, addr)
	if err != nil {
		fmt.Println(err)
	}
	conn.SetDeadline(time.Time{})
	return conn
}

func main() {

	var salt []byte
	conn := getConnection("tcp", "127.0.0.1:20996")

	// 服务端发送 Initial Handshake Packet 客户端接收后回复 Handshake Response Packet
	// https://dev.mysql.com/doc/internals/en/plain-handshake.html
	// 下面客户端开始接受initial packet https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
	msg := make([]byte, 100)
	n, err := conn.Read(msg)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", n)
	fmt.Printf("%v\n", msg)

	sequence := msg[3]
	fmt.Printf("sequence %v\n", sequence)

	payload := msg[4:]
	protocol_version := payload[0]

	counter := 1

	fmt.Printf("protocol_version %v\n", uint32(protocol_version))
	index := bytes.IndexByte(payload, 00)
	server_version := string(payload[counter:index])

	counter = index + 1
	fmt.Printf("server version %v\n", server_version)

	fmt.Printf("counter %v\n", counter)

	c := payload[counter : counter+4]
	fmt.Printf("connection bytes %v\n", c)

	cid := int(uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24)

	counter = counter + 4
	fmt.Printf("connect_id %v\n", cid)

	salt = append(salt, payload[counter:counter+8]...)
	authplugindatapart_1 := (payload[counter : counter+8])
	counter = counter + 8
	fmt.Printf("authplugindatapart_1 %v\n", authplugindatapart_1)

	filter := payload[counter]
	counter = counter + 1
	fmt.Printf("filter %v\n", filter)

	capability_flag_1 := payload[counter : counter+2]
	counter = counter + 2
	fmt.Printf("capability_flag_1 %v\n", capability_flag_1)

	if len(payload) > counter {
		character_set := payload[counter]
		counter = counter + 1
		fmt.Printf("character_set %v\n", character_set)

		status := payload[counter : counter+2]
		counter = counter + 2
		fmt.Printf("status %v\n", status)

		capability_flag_2 := payload[counter : counter+2]

		counter = counter + 2
		fmt.Printf("capability_flag_2 %v\n", capability_flag_2)

		counter = counter + 10 + 1

		salt = append(salt, payload[counter:counter+12]...)

		fmt.Printf("salt %v\n", salt)
	}

	// 客户端写回复writeHandshakeResponse41

	capability := CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION |
		CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS | CLIENT_LONG_FLAG

	length := 4 + 4 + 1 + 23

	user := "msandbox"
	password := "msandbox"
	db := "bai"
	length = length + len(user) + 1
	fmt.Printf("salt calcpassword %v\n", salt)

	auth := CalcPassword(salt, []byte(password))

	length += 1 + len(auth)

	if len(db) > 0 {
		capability |= CLIENT_CONNECT_WITH_DB

		length += len(db) + 1
	}

	data := make([]byte, length+4)

	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)

	// //Charset [1 byte]
	data[12] = byte(33)

	pos := 13 + 23

	pos += copy(data[pos:], user)

	// 1              length of auth-response
	pos++

	data[pos] = byte(len(auth))
	pos += 1 + copy(data[pos+1:], auth)

	if len(db) > 0 {
		pos += copy(data[pos:], db)
		//data[pos] = 0x00
	}

	length = len(data) - 4
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = sequence + 1
	_, err = conn.Write(data)

	if err != nil {
		fmt.Println("write fail" + err.Error())
	}

	fmt.Printf("write data %v\n", data)
	// read ok
	okmsg := make([]byte, 100)
	_, err = conn.Read(okmsg)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("okmsg = %v\n", okmsg)
	if okmsg[4] == OK_HEADER {
		fmt.Println("ok")
	} else if okmsg[4] == ERR_HEADER {
		code := okmsg[5:7]
		fmt.Printf("err code %v \n", code)
		// errcode := BytesToInt(code)
		// uint16是2个字节
		errcode := int(uint16(code[0]) | uint16(code[1])<<8)
		fmt.Printf("errcode code %v \n", errcode)
	}

	// 向服务端发送ping命令 https://dev.mysql.com/doc/internals/en/com-ping.html
	ping := []byte{0x01, //1 bytes long
		0x00,
		0x00,
		0x00, //sequence
		0x0e,
	}

	_, err = conn.Write(ping)

	if err != nil {
		fmt.Println("ping fail" + err.Error())
	}

	pingmsg := make([]byte, 100)
	_, err = conn.Read(pingmsg)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("pingmsg = %v\n", pingmsg)
	if pingmsg[4] == OK_HEADER {
		fmt.Println("ok")
		respons := pingmsg[4]
		fmt.Println((respons))

	} else if pingmsg[4] == ERR_HEADER {
		code := pingmsg[5:7]
		fmt.Printf("err code %v \n", code)
		// errcode := BytesToInt(code)
		// uint16是2个字节
		errcode := int(uint16(code[0]) | uint16(code[1])<<8)
		fmt.Printf("errcode code %v \n", errcode)
	}

	// 发送use db命令
	arg := "test"
	length = len(arg) + 1

	usedb := make([]byte, length+4)
	// https://dev.mysql.com/doc/internals/en/com-init-db.html
	usedb[4] = 0x02
	copy(usedb[5:], arg)
	fmt.Printf("usedb = %v \n", usedb)

	length = len(usedb) - 4
	usedb[0] = byte(length)
	usedb[1] = byte(length >> 8)
	usedb[2] = byte(length >> 16)
	usedb[3] = 0
	_, err = conn.Write(usedb)

	if err != nil {
		fmt.Println("usedb fail" + err.Error())
	}

	usedbmsg := make([]byte, 100)
	_, err = conn.Read(usedbmsg)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("usedbmsg = %v\n", usedbmsg)
	if usedbmsg[4] == OK_HEADER {
		fmt.Println("ok")
		respons := usedbmsg[4]
		fmt.Println((respons))

	} else if usedbmsg[4] == ERR_HEADER {
		code := usedbmsg[5:7]
		fmt.Printf("err code %v \n", code)
		// errcode := BytesToInt(code)
		// uint16是2个字节
		errcode := int(uint16(code[0]) | uint16(code[1])<<8)
		fmt.Printf("errcode code %v \n", errcode)
	}

	fmt.Println([]byte("test"))
	// dbname := usedbmsg[]

	// 向服务器发送查询命令send query
	arg = "select * from test.dba_test"

	fmt.Printf("args bytes = %v\n", []byte(arg))
	length = len(arg) + 1

	query := make([]byte, length+4)
	query[4] = 3
	copy(query[5:], arg)

	length = len(query) - 4
	query[0] = byte(length)
	query[1] = byte(length >> 8)
	query[2] = byte(length >> 16)
	query[3] = 0

	fmt.Printf("query = %v \n", query)

	n, err = conn.Write(query)

	if err != nil {
		fmt.Println(" query write fail" + err.Error())
	}

	if n != len(query) {
		fmt.Printf("connection was bad ")
	}
	fmt.Printf("send query length %v\n", n)

	// read result set

	header := []byte{0, 0, 0, 0}
	// var br *bufio.Reader
	var br = bufio.NewReaderSize(conn, 1024)

	_, err = io.ReadFull(br, header)

	if err != nil {
		fmt.Println("read query error", err)
	}
	// 第一次返回的是列的个数
	length = int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	fmt.Printf("result header =%v\n", header)
	fmt.Printf("result len =%v\n", length)

	data = make([]byte, length)

	if _, err := io.ReadFull(br, data); err != nil {
		fmt.Println("bad connection")
	}
	columnNumber := data[0]
	fmt.Printf("column number =%v\n", data)

	sequence = uint8(header[3])

	// 开始读取column Definition,读取到eof packet为止
	col := make(map[string]byte, data[0])
	for {
		header = []byte{0, 0, 0, 0}
		// var br *bufio.Reader
		// var br = bufio.NewReaderSize(conn, 1024)

		_, err = io.ReadFull(br, header)
		if err != nil {
			fmt.Println("read column error", err)
		}

		if err != nil {
			fmt.Println("read query error", err)
		}
		//
		length = int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
		fmt.Printf("length is = %v\n", length)
		data = make([]byte, length)
		_, err = io.ReadFull(br, data)

		if err != nil {
			fmt.Println("get column definition err", err.Error())
		}
		fmt.Printf("column def %v\n", data)
		// eof packet
		if data[0] == 254 {
			break
		}

		pos := 4
		schema_len := data[pos]
		fmt.Printf("schema length is %v\n", schema_len)
		pos = pos + 1
		fmt.Printf("pos %v\n", pos)
		schema := data[pos : pos+int(schema_len)]
		fmt.Printf("schema %v\n", schema)
		fmt.Printf("schema is %v\n", string(schema))
		pos = pos + int(schema_len)

		table_len := data[pos]
		pos = pos + 1
		table := data[pos : pos+int(table_len)]
		fmt.Printf("table %v\n", table)
		fmt.Printf("table is %v\n", string(table))
		pos = pos + int(table_len)

		org_table_len := data[pos]
		pos = pos + 1
		org_table := data[pos : pos+int(org_table_len)]
		fmt.Printf("org_table %v\n", org_table)
		fmt.Printf("org_table is %v\n", string(org_table))
		pos = pos + int(org_table_len)

		name_len := data[pos]
		pos = pos + 1
		name := data[pos : pos+int(name_len)]
		fmt.Printf("name %v\n", name)
		fmt.Printf("name is %v\n", string(name))
		pos = pos + int(name_len)

		org_name_len := data[pos]
		pos = pos + 1
		org_name := data[pos : pos+int(org_name_len)]
		fmt.Printf("org_name %v\n", org_name)
		fmt.Printf("org_name is %v\n", string(org_name))
		pos = pos + int(org_name_len)

		next_length := data[pos]
		pos = pos + 1
		fmt.Printf("next_length %v\n", next_length)

		charsetbyte := data[pos : pos+2]
		charset := int(uint16(charsetbyte[0]) | uint16(charsetbyte[1])<<8)
		pos = pos + 2
		fmt.Printf("charset is %v\n", charset)

		columnlenbyte := data[pos : pos+4]
		pos = pos + 4
		columnlen := int(uint32(columnlenbyte[0]) | uint32(columnlenbyte[1])<<8 | uint32(columnlenbyte[1])<<16 | uint32(columnlenbyte[1])<<24)
		fmt.Printf("columnlen is %v\n", columnlen)

		ctype := data[pos]
		pos = pos + 1
		fmt.Printf("column type is %v\n", ctype)

		col[string(schema)+"."+string(table)+"."+string(name)] = ctype
		flags := data[pos : pos+2]
		pos = pos + 2
		fmt.Printf("flag is %v\n", flags)

		decimals := data[pos : pos+1]
		pos = pos + 1
		fmt.Printf("decimals is %v\n", decimals)

		filter := data[pos : pos+2]
		pos = pos + 2
		fmt.Printf("filter is %v\n", filter)

		if len(data) > pos {
			default_len := data[pos]
			pos = pos + 1
			defaultval := data[pos : pos+int(default_len)]
			fmt.Printf("default value is %v\n", defaultval)
		}

	}

	// 读取行内容 Each row is a packet,
	fmt.Printf("the column number is %v\n", columnNumber)
	for {

		header = []byte{0, 0, 0, 0}
		// var br *bufio.Reader
		// var br = bufio.NewReaderSize(conn, 1024)

		_, err = io.ReadFull(br, header)
		if err != nil {
			fmt.Println("read row error", err)
		}

		if err != nil {
			fmt.Println("read query error", err)
		}
		//
		length = int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
		fmt.Printf("row length is = %v\n", length)
		data = make([]byte, length)
		_, err = io.ReadFull(br, data)

		if err != nil {
			fmt.Println("get row content err", err.Error())
		}
		fmt.Printf("row is %v\n", data)
		if data[0] == 254 {
			break
		}
		// 获取每一列的值
		pos = 0
		for j := 0; j < int(columnNumber); j++ {
			// 先按8字节算，否则第一个字节是一个判断值，按这个值判断后面几个字节是代表长度
			len := int(data[pos])
			pos = pos + 1

			if len == 0xfb {
				fmt.Printf("the value is null\n")
			} else {
				fmt.Printf("the value len is %v\n", len)
				value := data[pos : pos+len]
				pos = pos + len
				fmt.Printf("the value is %v\n", string(value))
			}
		}

	}

}
