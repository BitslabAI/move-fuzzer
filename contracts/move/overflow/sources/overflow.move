module overflow::math_u256 {
    const MAX_U256: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    public fun div_mod(num: u256, denom: u256): (u256, u256) {
        let p = num / denom;
        let r: u256 = num - (p * denom);
        (p, r)
    }

    public fun shlw(n: u256): u256 {
        n << 64
    }

    public fun shrw(n: u256): u256 {
        n >> 64
    }

    public fun checked_shlw(n: u256): (u256, bool) {
        let mask = 0xffffffffffffffff << 192;
        if (n > mask) {
            (0, true)
        } else {
            ((n << 64), false)
        }
    }

    public fun div_round(num: u256, denom: u256, round_up: bool): u256 {
        let p = num / denom;
        if (round_up && ((p * denom) != num)) {
            p + 1
        } else {
            p
        }
    }

    public fun add_check(num1: u256, num2: u256): bool {
        (MAX_U256 - num1 >= num2)
    }

    public entry fun div_mod_entry(num: u256, denom: u256) {
        div_mod(num, denom);
    }

    public entry fun shlw_entry(n: u256) {
        shlw(n);
    }

    public entry fun shrw_entry(n: u256) {
        shrw(n);
    }

    public entry fun checked_shlw_entry(n: u256) {
        checked_shlw(n);
    }

    public entry fun div_round_entry(num: u256, denom: u256, round_up: bool) {
        div_round(num, denom, round_up);
    }

    public entry fun add_check_entry(num1: u256, num2: u256) {
        add_check(num1, num2);
    }
}