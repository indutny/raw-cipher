#include "node.h"
#include "node_buffer.h"
#include "node_object_wrap.h"
#include "openssl/evp.h"
#include "v8.h"

namespace rawcipher {

using namespace node;
using namespace v8;

enum Kind {
  kCipher,
  kDecipher
};

template <Kind K>
class CipherBase : public ObjectWrap {
 public:
  static void Init(Handle<Object> target) {
    Local<FunctionTemplate> t = FunctionTemplate::New(CipherBase<K>::New);

    const char* name = K == kCipher ? "Cipher" : "Decipher";

    t->InstanceTemplate()->SetInternalFieldCount(1);
    t->SetClassName(String::NewSymbol(name));

    NODE_SET_PROTOTYPE_METHOD(t, "write", CipherBase<K>::Write);

    target->Set(String::New(name), t->GetFunction());
  }

 protected:
  CipherBase(const EVP_CIPHER* type, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX_init(&ctx_);
    bsize_ = EVP_CIPHER_block_size(type);

    int r = EVP_CipherInit_ex(&ctx_, type, NULL, key, iv, K == kCipher);
    assert(r == 1);
  }

  ~CipherBase() {
    EVP_CIPHER_CTX_cleanup(&ctx_);
  }

  static Handle<Value> Write(const Arguments& args) {
    HandleScope scope;

    if (args.Length() != 2 ||
        !Buffer::HasInstance(args[0]) ||
        !Buffer::HasInstance(args[1])) {
      return ThrowException(Exception::Error(String::New(
          "Invalid arguments length, expected write(out, in)")));
    }

    CipherBase<K>* b = ObjectWrap::Unwrap<CipherBase<K> >(args.This());
    EVP_CIPHER_CTX* ctx;

    ctx = &b->ctx_;

    unsigned char* out = reinterpret_cast<unsigned char*>(
        Buffer::Data(args[0]));
    size_t outl = Buffer::Length(args[0]);

    unsigned char* in = reinterpret_cast<unsigned char*>(Buffer::Data(args[1]));
    size_t inl = Buffer::Length(args[1]);
    if (inl % b->bsize_ != 0) {
      return ThrowException(Exception::Error(String::New(
          "Input length mod block size != 0")));
    }
    if (outl != inl) {
      return ThrowException(Exception::Error(String::New(
          "Input should have the same size as output")));
    }

    EVP_Cipher(ctx, out, in, inl);

    return scope.Close(Null());
  }

  static Handle<Value> New(const Arguments& args) {
    HandleScope scope;

    if (args.Length() != 3 ||
        !args[0]->IsString() ||
        !Buffer::HasInstance(args[1]) ||
        !Buffer::HasInstance(args[2])) {
      return ThrowException(Exception::Error(String::New(
          "Invalid arguments length, expected "
          "new Cipher/Decipher(type, key, iv)")));
    }

    String::Utf8Value v(args[0].As<String>());
    const EVP_CIPHER* type = EVP_get_cipherbyname(*v);
    if (type == NULL) {
      return ThrowException(Exception::Error(String::Concat(
          String::New("Invalid cipher type"),
          args[0].As<String>())));
    }

    if (static_cast<int>(Buffer::Length(args[1])) !=
            EVP_CIPHER_key_length(type)) {
      return ThrowException(Exception::Error(String::New(
          "Invalid key length")));
    }

    if (static_cast<int>(Buffer::Length(args[2])) !=
            EVP_CIPHER_iv_length(type)) {
      return ThrowException(Exception::Error(String::New(
          "Invalid iv length")));
    }

    CipherBase<K>* b = new CipherBase<K>(
        type,
        reinterpret_cast<unsigned char*>(Buffer::Data(args[1])),
        reinterpret_cast<unsigned char*>(Buffer::Data(args[2])));
    b->Wrap(args.This());

    return scope.Close(args.This());
  }

  EVP_CIPHER_CTX ctx_;
  int bsize_;
};

static void Init(Handle<Object> target) {
  // Init OpenSSL
  OpenSSL_add_all_algorithms();

  CipherBase<kCipher>::Init(target);
  CipherBase<kDecipher>::Init(target);
}

NODE_MODULE(rawcipher, Init);

}  // namespace rawcipher
