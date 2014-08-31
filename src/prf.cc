#include "node.h"
#include "nan.h"
#include "node_buffer.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "v8.h"

namespace prf {

using namespace node;
using namespace v8;

class StackMacCtx {
 public:
  StackMacCtx(const EVP_MD* type, const char* key, int key_len)
      : type_(type),
        key_(key),
        key_len_(key_len) {
    HMAC_CTX_init(ctx());
  }

  ~StackMacCtx() {
    HMAC_CTX_cleanup(ctx());
  }

  inline void Init() {
    int r = HMAC_Init_ex(&ctx_, key_, key_len_, type_, NULL);
    assert(r == 1);
  }

  inline HMAC_CTX* ctx() { return &ctx_; }

 private:
  const EVP_MD* type_;
  HMAC_CTX ctx_;
  const char* key_;
  int key_len_;
};

class StackMac {
 public:
  StackMac(StackMacCtx* ctx) : ctx_(ctx) {
    ctx->Init();
  }

  inline void Update(char* data, size_t len) {
    HMAC_Update(ctx_->ctx(), reinterpret_cast<unsigned char*>(data), len);
  }

  inline void Final(char* out, size_t len) {
    unsigned int olen;
    olen = len;
    HMAC_Final(ctx_->ctx(), reinterpret_cast<unsigned char*>(out), &olen);
    assert(olen == len);
  }

 private:
  StackMacCtx* ctx_;
};

static NAN_METHOD(Generate) {
  NanScope();

  if (args.Length() < 4 ||
      !Buffer::HasInstance(args[0]) ||
      !args[1]->IsString() ||
      !Buffer::HasInstance(args[2]) ||
      !Buffer::HasInstance(args[3])) {
    return NanThrowError("Invalid arguments length, expected "
                         "generate(out, type, key, seeds...)");
  }

  char* out = Buffer::Data(args[0]);
  unsigned int out_len = Buffer::Length(args[0]);

  String::Utf8Value v(args[1].As<String>());
  const char* v8name = *v;
  char name[256];
  strncpy(name, v8name, sizeof(name));

  // Count digests
  int digest_count = 0;
  for (char* p = name; p != NULL; p = strchr(p, '/')) {
    digest_count++;
    p++;
  }

  char* key = Buffer::Data(args[2]);
  int key_len = Buffer::Length(args[2]);
  int key_delta = 0;

  // Split keys between digests
  if (digest_count > 1) {
    key_delta = key_len / digest_count;
    key_len = key_delta;
  }

  // For each digest - compute PRF output and xor it with previous outputs
  char* pname = name;
  char* next_name;
  for (int i = 0; pname != NULL; pname = next_name, i++, key += key_delta) {
    char* pout = out;
    unsigned int pout_len = out_len;

    next_name = strchr(pname, '/');
    if (next_name != NULL) {
      pname[next_name - pname] = '\0';
      next_name++;
    }
    const EVP_MD* type = EVP_get_digestbyname(pname);

    if (type == NULL) {
      char buf[1024];
      snprintf(buf,
               sizeof(buf),
               "Invalid digest type: %s",
               *v);
      return NanThrowError(buf);
    }

    unsigned int DATA_len = EVP_MD_size(type);
    char A[DATA_len];
    char DATA[DATA_len];

    StackMacCtx ctx(type, key, key_len);

    // Initialize A1 = HMAC_hash(secret, A0)
    // A0 = seed
    {
      StackMac a1_mac(&ctx);

      for (int i = 3; i < args.Length(); i++)
        a1_mac.Update(Buffer::Data(args[i]), Buffer::Length(args[i]));
      a1_mac.Final(A, DATA_len);
    }

    // HMAC_hash(secret, A(i) + seed) + ...
    while (pout_len != 0) {
      unsigned int to_copy = pout_len > DATA_len ? DATA_len : pout_len;

      {
        StackMac data_mac(&ctx);
        data_mac.Update(A, DATA_len);
        for (int i = 3; i < args.Length(); i++)
          data_mac.Update(Buffer::Data(args[i]), Buffer::Length(args[i]));

        if (i == 0) {
          if (to_copy == DATA_len) {
            data_mac.Final(pout, to_copy);
          } else {
            data_mac.Final(DATA, DATA_len);
            memcpy(pout, DATA, to_copy);
          }
        } else {
          data_mac.Final(DATA, DATA_len);
          for (unsigned int j = 0; j < to_copy; j++)
            pout[j] ^= DATA[j];
        }
      }

      pout_len -= to_copy;
      pout += to_copy;
      if (pout_len == 0)
        break;

      // Update A
      {
        StackMac a_mac(&ctx);
        a_mac.Update(A, DATA_len);
        a_mac.Final(A, DATA_len);
      }
    }
  }

  NanReturnUndefined();
}

static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  NODE_SET_METHOD(target, "generate", Generate);
}

NODE_MODULE(prf, Init);

}  // namespace rawcipher
