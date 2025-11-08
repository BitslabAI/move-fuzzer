module lend_config::config {

    use aptos_std::type_info::{type_name};
    use std::vector;
    use std::error;
    use std::signer;
    use std::string::String;

    const EALREADY_PUBLISHED_CONFIG: u64 = 1;
    const ENOT_FOUND_CONFIG: u64 = 2;
    const ETOTAL_WEIGHT_NOT_EQUALS_100: u64 = 3;
    const EWEIGHT_EQUALS_ZERO: u64 = 4;
    const ENOT_FOUND_COIN_TYPE: u64 = 5;
    const ELTV_MORE_THAN_100_OR_EQUALS_ZERO: u64 = 6;
    const EFEES_MORE_THAN_100: u64 = 7;
    const EALREADY_ADDED: u64 = 8;
    const ENOT_ALLOWED: u64 = 9;
    const UNKNOW_OPER_TYPE: u64 = 10;
    const ELTV_OR_WEIGHT_EQUALS_ZERO: u64 = 11;

    const ENOT_EXISTS_APN_REWARD: u64 = 2001;
    const ENOT_EXISTS_FEES: u64 = 2002;
    const ENOT_EXISTS_LTV: u64 = 2003;
    const ENOT_EXISTS_DEPOSIT_LIMIT: u64 = 2004;

    /// annualized apn reward
    const DEFAULT_REWARD: u64 = 6000000000000;
    const DEFAULT_REWARD_STAKE: u64 = 3650000000000;
    const DEFAULT_FINES: u64 = 5;
    const APN_DURATION: u64 = 365 * 24 * 60 * 60;

    struct Store has copy, drop, store {
        ct: String,
        // should mul by 100
        ltv: u8,
        // should mul by 100
        fees: u8,
        weight: u8,
        deposit_limit: u64,
    }

    struct Config has key {
        total_apn_rewards: u64,
        total_apn_rewards_stake: u64,
        stores: vector<Store>,
    }

    fun sum(stores: &vector<Store>): u64 {
        let len = vector::length(stores);
        let i = 0;
        let sum: u64 = 0;
        while (i < len) {
            let store = vector::borrow(stores, i);
            sum = sum + (store.weight as u64);
            i = i + 1;
        };

        sum
    }

    fun contains(stores: &vector<Store>, ct: &String): (bool, u64) {
        let i = 0;
        let len = vector::length(stores);
        while (i < len) {
            let store = vector::borrow(stores, i);
            if (store.ct == *ct) {
                return (true, i)
            };
            i = i + 1;
        };
        (false, 0)
    }

    fun validate_account(account: &signer) {
        let account_addr = signer::address_of(account);

        assert!(account_addr == @lend_config, error::permission_denied(ENOT_ALLOWED));

        assert!(exists<Config>(account_addr), error::not_found(ENOT_FOUND_CONFIG));
    }

    public entry fun initialize(account: &signer) {
        let account_addr = signer::address_of(account);

        assert!(account_addr == @lend_config, error::permission_denied(ENOT_ALLOWED));

        assert!(!exists<Config>(account_addr), error::not_found(EALREADY_PUBLISHED_CONFIG));

        move_to(account, Config {
            total_apn_rewards: DEFAULT_REWARD,
            total_apn_rewards_stake: DEFAULT_REWARD_STAKE,
            stores: vector::empty(),
        })
    }

    public entry fun add<C>(account: &signer, ltv: u8, fees: u8, weight: u8, deposit_limit: u64) acquires Config {
        assert!(fees < 100, error::invalid_argument(EFEES_MORE_THAN_100));

        assert!(ltv < 100 && ltv != 0, ELTV_MORE_THAN_100_OR_EQUALS_ZERO);

        assert!(weight != 0, EWEIGHT_EQUALS_ZERO);

        validate_account(account);

        let config = borrow_global_mut<Config>(@lend_config);

        let type_name = type_name<C>();

        let (e, _i) = contains(&config.stores, &type_name);
        if (e) {
            abort EALREADY_ADDED
        };

        vector::push_back(&mut config.stores, Store { ct: type_name, ltv, fees, weight, deposit_limit});

        //todo: call update apn

    }

    public entry fun remove<C>(account: &signer) acquires Config {
        validate_account(account);

        let config = borrow_global_mut<Config>(@lend_config);

        let type_name = type_name<C>();

        let (e, i) = contains(&config.stores, &type_name);
        if (e) {
            vector::remove(&mut config.stores, i)
        } else {
            abort ENOT_FOUND_COIN_TYPE
        };
    }

    fun borrow_mut(account: &signer, ct: &String): Store acquires Config {
        validate_account(account);

        let config = borrow_global_mut<Config>(@lend_config);

        let (e, i) = contains(&config.stores, ct);
        if (e) {
            *vector::borrow_mut(&mut config.stores, i)
        } else {
            abort ENOT_FOUND_COIN_TYPE
        }
    }

    public entry fun set_weight<C>(account: &signer, new_w: u8) acquires Config {
        let type_name = type_name<C>();

        let store = borrow_mut(account, &type_name);

        store.weight = new_w
    }

    public entry fun set_ltv<C>(account: &signer, new_ltv: u8) acquires Config {
        assert!(new_ltv < 100 && new_ltv != 0, error::invalid_argument(ELTV_MORE_THAN_100_OR_EQUALS_ZERO));

        let type_name = type_name<C>();

        let store = borrow_mut(account, &type_name);

        store.ltv = new_ltv
    }

    public entry fun set_fees<C>(account: &signer, new_fees: u8) acquires Config {
        assert!(new_fees < 100, error::invalid_argument(EFEES_MORE_THAN_100));

        let type_name = type_name<C>();

        let store = borrow_mut(account, &type_name);

        store.fees = new_fees
    }



    public entry fun set_apn_reward_stake<C>(account: &signer, new_reward: u64) acquires Config {
        validate_account(account);

        let config = borrow_global_mut<Config>(@lend_config);

        config.total_apn_rewards_stake = new_reward
    }

    public entry fun set_apn_reward<C>(account: &signer, new_reward: u64) acquires Config {
        validate_account(account);

        let config = borrow_global_mut<Config>(@lend_config);

        config.total_apn_rewards = new_reward
    }

    public entry fun set_deposit_limit<C>(account: &signer, new_deposit_limit: u64) acquires Config {
        validate_account(account);

        assert!(new_deposit_limit > 100, error::invalid_argument(EFEES_MORE_THAN_100));

        let config = borrow_global_mut<Config>(@lend_config);

        let type_name = type_name<C>();

        let (e, i) = contains(&config.stores, &type_name);
        if (e) {
            let store = vector::borrow_mut(&mut config.stores, i);
            store.deposit_limit = new_deposit_limit;
        } else {
            abort ENOT_FOUND_COIN_TYPE
        };
    }

    /// Return APN reward for each coin
    public fun apn_reward<C>(): u64 acquires Config {
        assert!(exists<Config>(@lend_config), error::not_found(ENOT_FOUND_CONFIG));

        let config = borrow_global<Config>(@lend_config);

        let type_name = type_name<C>();

        let (e, i) = contains(&config.stores, &type_name);

        if (e) {
            let sum_quota = sum(&config.stores);
            let store = vector::borrow(&config.stores, i);
            let r = (config.total_apn_rewards as u128) * (store.weight as u128) / (APN_DURATION * sum_quota * 2 as u128);
            (r as u64)
        } else {
            abort ENOT_EXISTS_APN_REWARD
        }
    }

    /// Return APN reward for each coin
    public fun apn_reward_with_name(type_name: &String): u64 acquires Config {
        assert!(exists<Config>(@lend_config), error::not_found(ENOT_FOUND_CONFIG));

        let config = borrow_global<Config>(@lend_config);

        let (e, i) = contains(&config.stores, type_name);

        if (e) {
            let sum_quota = sum(&config.stores);
            let store = vector::borrow(&config.stores, i);
            let r = (config.total_apn_rewards as u128) * (store.weight as u128) / (APN_DURATION * sum_quota * 2 as u128);
            (r as u64)
        } else {
            abort ENOT_EXISTS_APN_REWARD
        }
    }

    /// Return APN reward for stake
    public fun apn_reward_stake<C>(): u64 acquires Config {
        assert!(exists<Config>(@lend_config), error::not_found(ENOT_FOUND_CONFIG));

        let config = borrow_global<Config>(@lend_config);

        config.total_apn_rewards_stake
    }

    /// Return APN reward per seconds for stake, the result is extended 100 times
    public fun apn_reward_stake_per_secs<C>(): u64 acquires Config {
        let r = apn_reward_stake<C>();

        r / APN_DURATION
    }

    fun borrow(ct: &String): Store acquires Config {
        assert!(exists<Config>(@lend_config), error::not_found(ENOT_FOUND_CONFIG));
        let config = borrow_global<Config>(@lend_config);

        let (e, i) = contains(&config.stores, ct);

        if (e) {
            *vector::borrow(&config.stores, i)
        } else {
            abort ENOT_EXISTS_FEES
        }
    }

    /// Return service fees, the result is extended 100 times
    public fun fees<C>(): u8 acquires Config {
        let type_name = type_name<C>();

        let store = borrow(&type_name);
        store.fees
    }

    /// Return LTV, the result is extended 100 times
    public fun ltv<C>(): u8 acquires Config {
        let type_name = type_name<C>();

        ltv_with_coin_type(&type_name)
    }

    /// Return LTV, the result is extended 100 times
    public fun ltv_with_coin_type(ct: &String): u8 acquires Config {
        let store = borrow(ct);
        store.ltv
    }

    /// Return how many is the limit amount when deposit
    public fun deposit_limit<C>(): u64 acquires Config {
        let type_name = type_name<C>();

        let store = borrow(&type_name);

        store.deposit_limit
    }

}