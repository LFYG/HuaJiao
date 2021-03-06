//
//  make_pack.cpp
//  HuaJiao
//
//  Created by LowBoy on 2017/8/12.
//  Copyright © 2017年 @LowBoyTeam. All rights reserved.
//


#include "make_pack.hpp"

#include <sstream>

#include "global.hpp"
#include "json11/json11.hpp"
#include "crypto/rc4/rc4.hpp"
#include "utils/utils.hpp"

using namespace json11;


//_newAddressBookRequestMessage
void new_request_message(PACKET_TYPE msgid, void* req_object, qihoo::protocol::messages::Message *message)
{
    message->set_msgid(msgid);
    message->set_sn(g_UserInfo.sn);
    message->set_sender(g_UserInfo.sender);
    message->set_sender_type(g_Config.senderType);
    
    auto *req = new qihoo::protocol::messages::Request();
    
    switch (msgid)
    {
        case LoginReq:
            req->set_allocated_login(reinterpret_cast<qihoo::protocol::messages::LoginReq*>(req_object));
            break;
        case ChatReq:
            req->set_allocated_chat(reinterpret_cast<qihoo::protocol::messages::ChatReq*>(req_object));
            break;
        case GetInfoReq:
            req->set_allocated_get_info(reinterpret_cast<qihoo::protocol::messages::GetInfoReq*>(req_object));
            break;
        case LogoutReq:
            req->set_allocated_logout(reinterpret_cast<qihoo::protocol::messages::LogoutReq*>(req_object));
            break;
        case InitLoginReq:
            req->set_allocated_init_login_req(reinterpret_cast<qihoo::protocol::messages::InitLoginReq*>(req_object));
            break;
        case Service_Req:
            req->set_allocated_service_req(reinterpret_cast<qihoo::protocol::messages::Service_Req*>(req_object));
            break;
        case Ex1QueryUserStatusReq:
            req->set_allocated_e1_query_user(reinterpret_cast<qihoo::protocol::messages::Ex1QueryUserStatusReq*>(req_object));
            break;
        case RestoreSessionReq:
            break;
        case QueryInfoReq:
            break;
        case QueryUserStatusReq:
            break;
        case QueryUserRegReq:
            break;
        case ExQueryUserStatusReq:
            break;
        case QueryPeerMsgMaxIdReq:
            break;
        case QueryConvSummaryReq:
            break;
        case UpdateSessionReq:
            break;
        default:
            break;
    }
    
    message->set_allocated_req(req);
}


//_sendHandshakePack
std::string new_hand_shark_pack()
{
    auto *init_login_req = new qihoo::protocol::messages::InitLoginReq();
    init_login_req->set_client_ram(g_UserInfo.client_ram);
    init_login_req->set_sig(g_UserInfo.sign);
    
    qihoo::protocol::messages::Message msg;
    new_request_message(InitLoginReq, init_login_req, &msg);
    
    std::string msgc = msg.SerializeAsString();
    
    std::cout << GREEN << "\n[HandshakePack] packet = " << RED;
    print_hex((unsigned char*)msgc.c_str(), msg.ByteSize());
    
    std::string out_result;
    rc4_xx(msgc, g_Config.defaultKey, &out_result);
    
    char szHeader[12] = { 113,104,16,101,8,32,0,0,0,0,0,0 };
    
    int length = int(out_result.length() + 12 + 4);
    int32_t ulength = swapInt32(length);
    
    std::stringstream mystream;
    mystream.write(szHeader, 12);
    mystream.write((char*)&ulength, 4);
    mystream.write(out_result.c_str(), out_result.length());
    
    std::string result = mystream.str();
    
    std::cout << GREEN << "[HandshakePack] encrypt packet = " << RED;
    print_hex((unsigned char*)result.c_str(), (int)result.length());
    
    return result;
}

//_sendLoginPack
std::string new_login_pack()
{
    auto *login = new qihoo::protocol::messages::LoginReq();
    login->set_app_id(g_Config.appId);
    login->set_server_ram(g_UserInfo.server_ram);
    
    std::stringstream secret_ram_stream;
    secret_ram_stream.write(g_UserInfo.server_ram.c_str(), g_UserInfo.server_ram.length());
    secret_ram_stream.write(randomString(8).c_str(), 8);
    
    std::string secret_ram;
    rc4_xx(secret_ram_stream.str(), g_UserInfo.password, &secret_ram);
    login->set_secret_ram(secret_ram);
    
    std::string verf_code;
    makeVerfCode(g_UserInfo.userid, &verf_code);
    login->set_verf_code(verf_code);
    
    login->set_net_type(4);
    login->set_mobile_type(MOBILE_PC);
    login->set_not_encrypt(true);
    login->set_platform("h5");
    
    qihoo::protocol::messages::Message msg;
    new_request_message(LoginReq, login, &msg);
    
    std::string msgc = msg.SerializeAsString();
    
    std::cout << GREEN << "\n[LoginReq] packet = " << RED;
    print_hex((unsigned char*)msgc.c_str(), msg.ByteSize());
    
    std::string out_result;
    rc4_xx(msgc, g_Config.defaultKey, &out_result);
    
    int length = int(out_result.length() + 4);
    int32_t ulength = swapInt32(length);
    
    std::stringstream mystream;
    mystream.write((char*)&ulength, 4);
    mystream.write(out_result.c_str(), out_result.length());
    std::string result = mystream.str();
    
    std::cout << GREEN << "[LoginReq] encrypt packet = " << RED;
    print_hex((unsigned char*)result.c_str(), (int)result.length());
    
    return result;
}

//_sendJoinChatroomPack
std::string new_join_chat_room_pack()
{
    auto *room = new qihoo::protocol::chatroom::ChatRoom();
    room->set_roomid(g_UserInfo.roomId);
    
    auto *applyjoinchatroomreq = new qihoo::protocol::chatroom::ApplyJoinChatRoomRequest();
    applyjoinchatroomreq->set_roomid(g_UserInfo.roomId);
    applyjoinchatroomreq->set_userid_type(0);
    applyjoinchatroomreq->set_allocated_room(room);
    
    auto *to_server_data = new qihoo::protocol::chatroom::ChatRoomUpToServer();
    to_server_data->set_payloadtype(102);
    to_server_data->set_allocated_applyjoinchatroomreq(applyjoinchatroomreq);
    
    auto *packet = new qihoo::protocol::chatroom::ChatRoomPacket();
    
    std::string uuid;
    uuid = md5(randomString(20)).toStr();
    packet->set_uuid(uuid);
    
    packet->set_client_sn(g_UserInfo.sn);
    packet->set_roomid(g_UserInfo.roomId);
    packet->set_appid(g_Config.appId);
    packet->set_allocated_to_server_data(to_server_data);
    
    auto *service_req = new qihoo::protocol::messages::Service_Req();
    service_req->set_service_id(10000006);
    service_req->set_request(packet->SerializePartialAsString());
    
    qihoo::protocol::messages::Message msg;
    new_request_message(Service_Req, service_req, &msg);
    
    std::string msgc = msg.SerializeAsString();
    
    std::cout << GREEN << "\n[Service_Req] packet = " << RED;
    print_hex((unsigned char*)msgc.c_str(), msg.ByteSize());
    
    int length = msg.ByteSize() + 4;
    int32_t ulength = swapInt32(length);
    
    std::stringstream mystream;
    mystream.write((char*)&ulength, 4);
    mystream.write(msgc.c_str(), msgc.length());
    std::string result = mystream.str();
    
    std::cout << GREEN << "[Service_Req] encrypt packet = " << RED;
    print_hex((unsigned char*)result.c_str(), (int)result.length());
    
    return result;
}
