/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <thread>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <android-base/unique_fd.h>

#include "adbd_auth.h"
#include "adbd_auth_internal.h"

void Log(const std::string& msg) {
  LOG(INFO) << "(" << gettid() << "): " << msg;
}

using namespace std::string_view_literals;
using namespace std::string_literals;

constexpr std::string_view kUdsName = "\0adb_auth_test_uds"sv;
static_assert(kUdsName.size() <= sizeof(reinterpret_cast<sockaddr_un*>(0)->sun_path));

// Emulate android_get_control_socket which adbauth uses to get the Unix Domain Socket
// to communicate with Framework.
std::optional<int> CreateServerSocket() {
  int sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (sockfd == -1) {
    Log("Failed to create server socket");
    return {};
  }

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  memset(addr.sun_path, 0, sizeof(addr.sun_path));
  strncpy(addr.sun_path, kUdsName.data(), kUdsName.size());

  if (bind(sockfd, (struct sockaddr*) &addr, sizeof(sockaddr_un)) == -1) {
    Log("Failed to bind socket server to abstract namespace");
    return {};
  }

  if (listen(sockfd, 1) == -1) {
    Log("Failed to listen on socket server");
    return {};
  }

  return sockfd;
}

// This class behaves like AdbDebuggingManager.
//   - Open the UDS created by our adb_auth emulation layer
//   - Allow to send messages
//   - Allow to recv messages
class Framework {
 public:
  Framework() {
    socket_ = Connect();
  }

  std::string Recv() const {
    char msg[256];
    auto num_bytes_read = read(socket_, msg, sizeof(msg));
    Log("Framework read "s + std::to_string(num_bytes_read) + " bytes");
    return std::string(msg, num_bytes_read);
  }

  int Send(const std::string& msg) {
    return write(socket_, msg.data(), msg.size());
  }

  bool isReady() {
    return socket_ != -1;
  }

 private:
  int socket_;

  int Connect() {
    int sockfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sockfd == -1) {
      Log("Cannot create client socket");
      return -1;
    }

    sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, kUdsName.data(), kUdsName.size());

    if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
      Log("Cannot connect to socket server");
      return -1;
    }

    return sockfd;
  }
};

std::shared_ptr<AdbdAuthContext> CreateContext(const AdbdAuthCallbacks& cb) {
  auto server_socket = CreateServerSocket();
  if (!server_socket.has_value()) {
    Log("Cannot create context");
    return {};
  }

  std::shared_ptr<AdbdAuthContext> context;
  switch (cb.version) {
    case 1: {
      context =
          std::make_shared<AdbdAuthContext>(&reinterpret_cast<const AdbdAuthCallbacksV1&>(cb),
                                            server_socket.value());
      break;
    }
    case 2: {
      context =
          std::make_shared<AdbdAuthContextV2>(&reinterpret_cast<const AdbdAuthCallbacksV2&>(cb),
                                              server_socket.value());
      break;
    }
    default: {
      return {};
    }
  }
  context->InitFrameworkHandlers();

  std::thread([context]() {
    Log("Framework running");
    context->Run(); }).detach();
  return context;
}

TEST(AdbAuthTest, SendTcpPort) {
  AdbdAuthCallbacksV1 callbacks{};
  callbacks.version = 1;
  auto context = CreateContext(callbacks);
  if (context == nullptr) {
    FAIL();
  }


  Framework framework{};
  if (!framework.isReady()) {
    Log("Framework not initialized");
    FAIL();
  }

  // Send TLS to framework
  const uint8_t port = 19;
  adbd_auth_send_tls_server_port(context.get(), port);

  // Check that Framework received it.
  std::string msg = framework.Recv();
  ASSERT_EQ(4, msg.size());
  ASSERT_EQ(msg[0], 'T');
  ASSERT_EQ(msg[1], 'P');
  ASSERT_EQ(msg[2], port);
  ASSERT_EQ(msg[3], 0);
}
