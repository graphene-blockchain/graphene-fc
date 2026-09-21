#include <boost/test/unit_test.hpp>

#include <fc/crypto/dh.hpp>
#include <fc/exception/exception.hpp>

BOOST_AUTO_TEST_SUITE(fc_crypto)

BOOST_AUTO_TEST_CASE(dh_test)
{
    fc::diffie_hellman alice;
    BOOST_CHECK( alice.generate_params( 512, 5 ) );
    BOOST_CHECK( alice.generate_pub_key() );

    fc::diffie_hellman bob;
    bob.p = alice.p;
    BOOST_CHECK( bob.validate() );
    BOOST_CHECK( bob.generate_pub_key() );

    fc::diffie_hellman charlie;
    BOOST_CHECK( !charlie.validate() );
    BOOST_CHECK( !charlie.generate_pub_key() );
    charlie.p = alice.p;
    BOOST_CHECK( charlie.validate() );
    BOOST_CHECK( charlie.generate_pub_key() );

    BOOST_CHECK( alice.compute_shared_key( bob.pub_key ) );
    BOOST_CHECK( bob.compute_shared_key( alice.pub_key ) );
    BOOST_CHECK_EQUAL( alice.shared_key.size(), bob.shared_key.size() );
    BOOST_CHECK( !memcmp( alice.shared_key.data(), bob.shared_key.data(), alice.shared_key.size() ) );
    std::vector<char> alice_bob = alice.shared_key;

    BOOST_CHECK( alice.compute_shared_key( charlie.pub_key ) );
    BOOST_CHECK( charlie.compute_shared_key( alice.pub_key ) );
    BOOST_CHECK_EQUAL( alice.shared_key.size(), charlie.shared_key.size() );
    BOOST_CHECK( !memcmp( alice.shared_key.data(), charlie.shared_key.data(), alice.shared_key.size() ) );
    std::vector<char> alice_charlie = alice.shared_key;

    BOOST_CHECK( charlie.compute_shared_key( bob.pub_key ) );
    BOOST_CHECK( bob.compute_shared_key( charlie.pub_key ) );
    BOOST_CHECK_EQUAL( charlie.shared_key.size(), bob.shared_key.size() );
    BOOST_CHECK( !memcmp( charlie.shared_key.data(), bob.shared_key.data(), bob.shared_key.size() ) );
    std::vector<char> bob_charlie = charlie.shared_key;

    BOOST_CHECK( alice_bob.size() != alice_charlie.size() ||  memcmp( alice_bob.data(), alice_charlie.data(), alice_bob.size() ) );

    BOOST_CHECK( alice_bob.size() != bob_charlie.size() || memcmp( alice_bob.data(), bob_charlie.data(), alice_bob.size() ) );

    BOOST_CHECK( alice_charlie.size() != bob_charlie.size() || memcmp( alice_charlie.data(), bob_charlie.data(), alice_charlie.size() ) );

    alice.p.clear(); alice.p.push_back(100); alice.p.push_back(2);
    BOOST_CHECK( !alice.validate() );
    alice.p = bob.p;
    alice.g = 9;
    BOOST_CHECK( !alice.validate() );
}

// 512-bit parameters: OpenSSL 3 rejects DH moduli below 512 bits.
// The shared key is one byte shorter than DH_size() to exercise the size mismatch path.
static const std::string P( std::string(
   "\xf1\x7a\x9c\xa3\xed\x40\xb0\x86\x65\xb3\x4a\xf4\x9f\xaa\xc8\xce"
   "\x98\xd1\xdf\x06\xd5\x3a\xde\x11\x70\xda\x46\x7f\x0c\x79\x6b\xb2"
   "\xa2\x89\xcf\x8c\x63\xf3\xbd\xad\xb0\x7e\xb0\x31\x36\x6d\x22\x21"
   "\x8a\x4b\xb7\xe0\xdc\xd6\xa7\xed\x28\x3d\x99\x60\xbf\x4f\x24\xa7", 64 ) );
static const std::string ALICE_PUB( std::string(
   "\xa7\x72\xc4\x57\xa1\x40\xbd\x6f\xf6\xe7\x90\x91\xbf\xf6\x24\xbc"
   "\x73\x12\x9b\x42\xc4\x2c\x4c\x3c\x23\x2c\x6b\x7e\xc4\x30\xa3\x35"
   "\x56\x62\xe4\x23\x34\xc2\xff\x73\x4c\x69\xac\x7b\xb8\xc5\xc2\x2e"
   "\x1e\xdd\x86\x5a\x14\x88\xf4\xae\xa4\xf7\x9c\x73\xe3\xa3\x03\x5d", 64 ) );
static const std::string ALICE_PRIV( std::string(
   "\x27\x45\xae\xd2\x1a\x9e\xc5\xf5\x73\xf2\xb0\x62\x38\xa2\x14\xf8"
   "\x42\xc4\x23\x9e\x1f\xba\x31\x2b\xd4\xb9\x75\xf9\x4b\xdd\xe3\x3b"
   "\xe8\x97\xf5\xa0\x4f\xeb\x6e\xb1\x7c\x40\x71\x6d\xc4\x76\x95\xc6"
   "\x93\x4f\x63\x9d\x52\x53\xee\x8d\xeb\xf4\x56\x45\xbe\x8b\xa3\x25", 64 ) );
static const std::string BOB_PUB( std::string(
   "\x6e\xe2\x13\x7b\xc1\x8c\x13\x07\x7a\x24\x25\x50\x72\xd5\x2a\x77"
   "\xc5\xd1\x03\xed\x13\x02\x9f\x10\xd9\x07\x97\x1d\xd5\x53\x99\x6e"
   "\xe6\x87\x92\x39\x58\x6d\x90\x6e\x81\xa4\x9e\xda\xf1\x7f\xab\x01"
   "\x6c\x31\xf9\xfc\x38\x28\x07\xe1\x4a\xff\x6f\x46\x42\x41\xe8\x27", 64 ) );
static const std::string BOB_PRIV( std::string(
   "\x3b\xfb\xc6\x4a\xba\xbe\x26\xbe\xee\x52\x35\xa2\x40\xa7\xbf\xc4"
   "\xbf\x7a\xe2\xeb\x75\x3a\xb1\xd1\x70\xe2\xc6\xd9\xcb\x6e\x9c\x07"
   "\x66\xc2\xd5\x55\xb4\x62\xbc\x5e\x92\x9a\x91\x80\x57\xe4\xcb\x4f"
   "\xe2\x88\xde\x85\x92\x27\xb1\xf9\xf0\xf3\x12\x06\xb6\x33\x80\xac", 64 ) );
static const std::string SHARED_KEY( std::string(
   "\x57\xb0\x69\xac\xa8\x03\xe8\xd9\x52\xa0\xbc\x4c\x2a\x05\xc5\x44"
   "\x7c\x6f\xd2\x33\xaa\x7b\x4e\x3d\x8e\xee\xfe\xf3\x6d\x68\xd3\xd3"
   "\x1d\x55\xaf\x6e\x0f\x75\xac\xfc\xb1\xf4\x46\x9c\x6e\xa7\xa9\xa2"
   "\x96\x3c\x44\x19\x9c\x50\x7f\xfb\x9e\x86\x09\x52\x60\xbd\xb0", 63 ) );
BOOST_AUTO_TEST_CASE(dh_size_mismatch_test)
{
   fc::diffie_hellman alice;
   alice.p.insert( alice.p.begin(), P.begin(), P.end() );
   alice.pub_key.insert( alice.pub_key.begin(), ALICE_PUB.begin(), ALICE_PUB.end() );
   alice.priv_key.insert( alice.priv_key.begin(), ALICE_PRIV.begin(), ALICE_PRIV.end() );
   alice.g = 5;
   BOOST_CHECK( alice.validate() );

   fc::diffie_hellman bob;
   bob.p = alice.p;
   bob.pub_key.insert( bob.pub_key.begin(), BOB_PUB.begin(), BOB_PUB.end() );
   bob.priv_key.insert( bob.priv_key.begin(), BOB_PRIV.begin(), BOB_PRIV.end() );
   bob.g = alice.g;
   BOOST_CHECK( bob.validate() );

   BOOST_CHECK( alice.compute_shared_key( bob.pub_key ) );
   BOOST_CHECK( bob.compute_shared_key( alice.pub_key ) );
   BOOST_CHECK_EQUAL( 63u, alice.shared_key.size() );
   BOOST_CHECK_EQUAL( 63u, bob.shared_key.size() );
   BOOST_CHECK( !memcmp( alice.shared_key.data(), bob.shared_key.data(), alice.shared_key.size() ) );

   BOOST_CHECK_EQUAL( SHARED_KEY, std::string( alice.shared_key.begin(), alice.shared_key.end() ) );
}

BOOST_AUTO_TEST_SUITE_END()
