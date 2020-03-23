/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */
#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

#include <string>

namespace eosiosystem
{
class system_contract;
}

namespace eosio
{

using internal_use_do_not_use::db_end_i64;
using internal_use_do_not_use::db_find_i64;
using internal_use_do_not_use::db_get_i64;
using internal_use_do_not_use::db_store_i64;
using internal_use_do_not_use::db_update_i64;
using std::string;

const eosio::symbol PEOS_SYMBOL = symbol(symbol_code("PEOS"), 4);

class [[eosio::contract("peos")]] peos : public eosio::contract
{
 public:
   using contract::contract;

   ACTION bench();
 private:
};

} // namespace eosio