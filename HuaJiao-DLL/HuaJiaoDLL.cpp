#define _CRT_SECURE_NO_WARNINGS

#include "HuaJiaoDLL.h"

#include <sstream>
#include <string>
#include <ctime>

#include "../HuaJiao/utils/utils.hpp"

#include "../HuaJiao/protocol/ChatRoom.pb.h"
#include "../HuaJiao/protocol/CommunicationData.pb.h"

#include "../HuaJiao/crypto/rc4/rc4.hpp"
#include "../HuaJiao/crypto/md5/md5.h"
#include "../HuaJiao/crypto/gzip/gzip.h"

#include "../HuaJiao/json11/json11.hpp"

using namespace json11;

#ifdef _WIN32
	#ifdef _DEBUG
		#pragma comment(lib,"libprotobuf_d.lib")
	#else
		#pragma comment(lib,"libprotobuf.lib")
	#endif // _DEBUG
#endif // _WIN32

inline void makeVerfCode(const std::string& text, std::string *outstr)
{
	*outstr = md5(text + "360tantan@1408$").toStr().substr(24, 8).c_str();
}

DWORD WINAPI MakeHandshakeRequestPack(
	const char* defaultKey,
	const char* uid,
	const char* sign,
	char* out_buffer, 
	const int out_buffer_size
)
{
	std::string client_ram = randomString(10);
	google::protobuf::uint64 sn = randomNumber(10);
	
	//std::string timestamp = convertToString(time(NULL)) + "00001";
	//google::protobuf::uint64 sn = convertToString<google::protobuf::uint64>(timestamp);
	
	auto *init_login_req = new qihoo::protocol::messages::InitLoginReq();
	init_login_req->set_client_ram(client_ram);
	init_login_req->set_sig(sign);

	auto *req = new qihoo::protocol::messages::Request();
	req->set_allocated_init_login_req(init_login_req);

	auto *msg = new qihoo::protocol::messages::Message();
	msg->set_msgid(InitLoginReq);
	msg->set_sn(sn);
	msg->set_sender(uid);
	msg->set_client_data(0);
	msg->set_sender_type("jid");
	msg->set_allocated_req(req);

	std::string msgc = msg->SerializeAsString();

	std::string out_result;
	rc4_xx(msgc, defaultKey, &out_result);

	char szHeader[12] = { 113,104,16,101,8,32,0,0,0,0,0,0 };

	int length = int(out_result.length() + 12 + 4);

	if (length > out_buffer_size)
		return 0;

	int32_t ulength = swapInt32(length);

	std::stringstream mystream;
	mystream.write(szHeader, 12);
	mystream.write((char*)&ulength, 4);
	mystream.write(out_result.c_str(), out_result.length());
	std::string result = mystream.str();

	memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);
	
	return length;
}


BOOL WINAPI ParseHandshakeResponsePack(
	const char* defaultKey,
	const void* response,
	const int response_size,
	char* server_ram,
	char* client_ram
)
{
	int length = response_size - 6;

	char *szBuffer = (char*)malloc(length);
	memset(szBuffer, 0, length);
	memcpy(szBuffer, (char*)response + 6, length);

	std::string out_result;
	rc4_xx(szBuffer, defaultKey, &out_result);

	free(szBuffer);

	qihoo::protocol::messages::Message *message = new qihoo::protocol::messages::Message();
	message->ParseFromArray(out_result.c_str(), out_result.length());

	if (message->msgid() == InitLoginResp)
	{
		auto response = message->resp().init_login_resp();
		strcpy(client_ram, response.client_ram().c_str());
		strcpy(server_ram, response.server_ram().c_str());
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}


DWORD WINAPI MakeLoginRequestPack(
	const char* defaultKey,
	const char* uid,
	const char* server_ram,
	const char* password,
	const char* mobileType,
	const char* platform,
	const char* deviceid,
	char* out_buffer,
	const int out_buffer_size
)
{
	google::protobuf::uint64 sn = randomNumber(10);

	auto *login = new qihoo::protocol::messages::LoginReq();
	login->set_app_id(2080);
	login->set_server_ram(server_ram);

	std::stringstream secret_ram_stream;
	secret_ram_stream.write(server_ram, strlen(server_ram));
	secret_ram_stream.write(randomString(8).c_str(), 8);

	std::string secret_ram;
	rc4_xx(secret_ram_stream.str(), password, &secret_ram);
	login->set_secret_ram(secret_ram);

	std::string verf_code;
	makeVerfCode(uid, &verf_code);
	login->set_verf_code(verf_code);

	login->set_net_type(4);
	login->set_mobile_type(mobileType);
	login->set_not_encrypt(true);
	login->set_platform(platform);
	login->set_deviceid(deviceid);

	auto *req = new qihoo::protocol::messages::Request();
	req->set_allocated_login(login);

	qihoo::protocol::messages::Message *message = new qihoo::protocol::messages::Message();
	message->set_msgid(LoginReq);
	message->set_sn(sn);
	message->set_sender(uid);
	message->set_sender_type("jid");
	message->set_allocated_req(req);
	
	std::string msgc = message->SerializeAsString();

	std::string out_result;
	rc4_xx(msgc, defaultKey, &out_result);

	int length = int(out_result.length() + 4);

	if (length > out_buffer_size)
		return 0;

	int32_t ulength = swapInt32(length);

	std::stringstream mystream;
	mystream.write((char*)&ulength, 4);
	mystream.write(out_result.c_str(), out_result.length());
	std::string result = mystream.str();

	memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

	return length;
}


BOOL WINAPI ParseLoginResponsePack(
	const char* defaultKey,
	const char* encryptKey,
	const void* response,
	const int response_size,
	char* session_id,
	char* session_key,
	char* client_login_ip,
	char* serverip
)
{
	int length = response_size - 4;

	char *szBuffer = (char*)malloc(length);
	memset(szBuffer, 0, length);
	memcpy(szBuffer, (char*)response + 4, length);

	std::string out_result;
	rc4_xx(szBuffer, encryptKey, &out_result);

	free(szBuffer);

	qihoo::protocol::messages::Message *message = new qihoo::protocol::messages::Message();
	message->ParseFromArray(out_result.c_str(), out_result.length());

	if (message->msgid() == LoginResp)
	{
		auto login = message->resp().login();
		strcpy(session_id, login.session_id().c_str());
		strcpy(session_key, login.session_key().c_str());
		strcpy(client_login_ip, login.client_login_ip().c_str());
		strcpy(serverip, login.serverip().c_str());
		return TRUE;
	}
	return FALSE;
}


DWORD WINAPI MakeJoinChatRoomRequestPack(
	const char* roomId,
	const char* uid,
	const char* session_key,
	char* out_buffer,
	const int out_buffer_size
)
{
	google::protobuf::uint64 sn = randomNumber(10);

	auto *room = new qihoo::protocol::chatroom::ChatRoom();
	room->set_roomid(roomId);

	auto *applyjoinchatroomreq = new qihoo::protocol::chatroom::ApplyJoinChatRoomRequest();
	applyjoinchatroomreq->set_roomid(roomId);
	applyjoinchatroomreq->set_userid_type(0);
	applyjoinchatroomreq->set_allocated_room(room);

	auto *to_server_data = new qihoo::protocol::chatroom::ChatRoomUpToServer();
	to_server_data->set_payloadtype(102);
	to_server_data->set_allocated_applyjoinchatroomreq(applyjoinchatroomreq);

	auto *packet = new qihoo::protocol::chatroom::ChatRoomPacket();

	std::string uuid;
	uuid = md5(randomString(20)).toStr();
	packet->set_uuid(uuid);

	packet->set_client_sn(sn);
	packet->set_roomid(roomId);
	packet->set_appid(2080);
	packet->set_allocated_to_server_data(to_server_data);

	auto *service_req = new qihoo::protocol::messages::Service_Req();
	service_req->set_service_id(10000006);
	service_req->set_request(packet->SerializePartialAsString());

	auto *req = new qihoo::protocol::messages::Request();
	req->set_allocated_service_req(service_req);

	qihoo::protocol::messages::Message *msg = new qihoo::protocol::messages::Message();
	msg->set_msgid(Service_Req);
	msg->set_sn(sn);
	msg->set_sender(uid);
	msg->set_sender_type("jid");
	msg->set_allocated_req(req);

	std::string msgc = msg->SerializeAsString();

	std::string out_result;
	if (session_key && *session_key != '\0')
	{	
		rc4_xx(msgc, session_key, &out_result);
	}
	else
	{
		out_result = msgc;
	}

	int length = int(out_result.length() + 4);

	if (length > out_buffer_size)
		return 0;

	int32_t ulength = swapInt32(length);

	std::stringstream mystream;
	mystream.write((char*)&ulength, 4);
	mystream.write(out_result.c_str(), out_result.length());
	std::string result = mystream.str();

	memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

	return length;
}


DWORD WINAPI MakeQuitChatRoomRequestPack(
	const char* roomId,
	const char* uid,
	const char* session_key,
	char* out_buffer,
	const int out_buffer_size
)
{
	google::protobuf::uint64 sn = randomNumber(10);

	auto *room = new qihoo::protocol::chatroom::ChatRoom();
	room->set_roomid(roomId);

	auto *quitchatroomreq = new qihoo::protocol::chatroom::QuitChatRoomRequest();
	quitchatroomreq->set_roomid(roomId);
	quitchatroomreq->set_allocated_room(room);

	auto *to_server_data = new qihoo::protocol::chatroom::ChatRoomUpToServer();
	to_server_data->set_payloadtype(103);
	to_server_data->set_allocated_quitchatroomreq(quitchatroomreq);

	auto *packet = new qihoo::protocol::chatroom::ChatRoomPacket();

	std::string uuid;
	uuid = md5(randomString(20)).toStr();
	packet->set_uuid(uuid);

	packet->set_client_sn(sn);
	packet->set_roomid(roomId);
	packet->set_appid(2080);
	packet->set_allocated_to_server_data(to_server_data);

	auto *service_req = new qihoo::protocol::messages::Service_Req();
	service_req->set_service_id(10000006);
	service_req->set_request(packet->SerializePartialAsString());

	auto *req = new qihoo::protocol::messages::Request();
	req->set_allocated_service_req(service_req);

	qihoo::protocol::messages::Message *msg = new qihoo::protocol::messages::Message();
	msg->set_msgid(Service_Req);
	msg->set_sn(sn);
	msg->set_sender(uid);
	msg->set_sender_type("jid");
	msg->set_allocated_req(req);

	std::string msgc = msg->SerializeAsString();

	std::string out_result;
	if (session_key && *session_key != '\0')
	{
		rc4_xx(msgc, session_key, &out_result);
	}
	else
	{
		out_result = msgc;
	}

	int length = int(out_result.length() + 4);

	if (length > out_buffer_size)
		return 0;

	int32_t ulength = swapInt32(length);

	std::stringstream mystream;
	mystream.write((char*)&ulength, 4);
	mystream.write(out_result.c_str(), out_result.length());
	std::string result = mystream.str();

	memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

	return length;
}

DWORD WINAPI ParseMessagePack(
	const void* response,
	const int response_size,
	char* out_buffer,
	const int out_buffer_size
)
{
	char* pData = (char*)response + 4;
	qihoo::protocol::messages::Message *message = new qihoo::protocol::messages::Message();
	message->ParseFromArray(pData, response_size - 4);
	int msgid = message->msgid();

	switch (msgid)
	{
		case Service_Resp:
		{
			auto service_resp = message->resp().service_resp();
			auto *chatRoomPacket = new qihoo::protocol::chatroom::ChatRoomPacket();
			chatRoomPacket->ParseFromString(service_resp.response());

			auto user_data = chatRoomPacket->to_user_data();
			int service_id = service_resp.service_id();
			int payloadtype = user_data.payloadtype();
			std::string reason = user_data.reason();

			if (payloadtype == ApplyJoinChatRoomResp)
			{
				if (user_data.result() == SuccessFul)
				{
					qihoo::protocol::chatroom::ApplyJoinChatRoomResponse applyjoinchatroomresp;
					applyjoinchatroomresp = user_data.applyjoinchatroomresp();
					qihoo::protocol::chatroom::ChatRoom room;
					room = applyjoinchatroomresp.room();

					std::string roomid = room.roomid();
					std::string userid = room.members(0).userid();
					std::string roomtype = room.roomtype();

					Json my_json = Json::object{
						{ "msgid", msgid },
						{ "service_id", service_id },
						{ "result",user_data.result() },
						{ "payloadtype",payloadtype },
						{ "reason",reason },
						{ "roomid",roomid },
						{ "userid",userid },
						{ "roomtype",roomtype },
						{"partnerdata",room.partnerdata()}
					};

					std::string result = my_json.dump();
					int length = result.length();

					if (length > out_buffer_size)
						return FALSE;

					memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

					return length;
				}
			}
			else if (payloadtype == QuitChatRoomResp)
			{
				auto quitchatroomresp = user_data.quitchatroomresp();
				auto room = quitchatroomresp.room();

				Json my_json = Json::object{
					{ "msgid", msgid },
					{ "service_id", service_id },
					{ "result",user_data.result() },
					{ "payloadtype",payloadtype },
					{ "reason",reason }
				};

				std::string result = my_json.dump();
				int length = result.length();

				if (length > out_buffer_size)
					return FALSE;

				memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

				return length;
			}

			std::string result = "[user_data] ->" + user_data.DebugString();
			memcpy_s(out_buffer, out_buffer_size, result.c_str(), result.length());
			return result.length();
		}
		case NewMessageNotify:
		{
			auto notify = message->notify();
			auto *chatRoomPacket = new qihoo::protocol::chatroom::ChatRoomPacket();
			chatRoomPacket->ParseFromString(notify.newinfo_ntf().info_content());
			auto user_data = chatRoomPacket->to_user_data();
			int payloadtype = user_data.payloadtype();

			if (payloadtype == NewmsgNotify)
			{
				auto chatroom_newmsg = user_data.newmsgnotify();
				Json my_json = Json::object{
					{ "msgid", msgid },
					{ "payloadtype",payloadtype },
					{ "msgcontent",chatroom_newmsg.msgcontent()}
				};
				std::string result = my_json.dump();
				int length = result.length();
				if (length > out_buffer_size)
					return FALSE;
				memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);
				return length;
			}
			else if (payloadtype == MemberJoinNotify)
			{
				auto memberJoinChatRoomNotify = user_data.memberjoinnotify();
				auto chatRoom = memberJoinChatRoomNotify.room();

				std::string value = chatRoom.properties(1).value();
				std::string userdata = chatRoom.members(0).userdata();

				Json my_json = Json::object{
					{ "msgid", msgid },
					{ "payloadtype",payloadtype },
					{ "value",value },
					{ "userdata",userdata }
				};

				std::string result = my_json.dump();
				int length = result.length();

				if (length > out_buffer_size)
					return FALSE;

				memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

				return length;
			}
			else if (payloadtype == MemberQuitNotify)
			{
				auto memberQuitChatRoomNotify = user_data.memberquitnotify();
				auto chatRoom = memberQuitChatRoomNotify.room();

				std::string userId = chatRoom.members(0).userid();
				std::string value = chatRoom.properties(0).value();

				Json my_json = Json::object{
					{ "msgid", msgid },
					{ "payloadtype",payloadtype },
					{ "value",value },
					{ "userId",userId }
				};

				std::string result = my_json.dump();
				int length = result.length();

				if (length > out_buffer_size)
					return FALSE;

				memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

				return length;
			}
			else if (payloadtype == MemberGzipNotify && user_data.multinotify().size() > 0)
			{
				std::stringstream sswrite;
				sswrite << "{";
				sswrite << "\"msgid\":";
				sswrite << msgid;
				sswrite << ",\"payloadtype\":";
				sswrite << payloadtype;
				sswrite << ",\"multinotify\":[";
				for (int i = 0; i < user_data.multinotify().size(); i++)
				{
					std::string data = user_data.multinotify(i).data();
					std::vector<unsigned char> unpack;
					std::vector<unsigned char> src_data;
					src_data.assign(data.begin(), data.end());
					if (gzip::ungzip(src_data, unpack))
					{
						qihoo::protocol::chatroom::ChatRoomNewMsg chatRoomNewmsg;
						chatRoomNewmsg.ParseFromArray(&unpack[0], unpack.size());
						std::string msgcontent = chatRoomNewmsg.msgcontent();
						Json my_json(msgcontent);
						sswrite << my_json.dump();
						if (i != user_data.multinotify().size())
							sswrite << ",";
					}
				}
				sswrite << "]}";

				std::string result = sswrite.str();
				int length = result.length();

				if (length > out_buffer_size)
					return FALSE;

				memcpy_s(out_buffer, out_buffer_size, result.c_str(), length);

				return length;
			}	
			//std::string result = "[newmsgnotify] ->" + chatRoomPacket->DebugString();
			//memcpy_s(out_buffer, out_buffer_size, result.c_str(), result.length());
			return 0;
		}		
		default:
			break;
	}
	return 0;
}