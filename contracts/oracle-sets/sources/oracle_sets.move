// For Move coding conventions, see
// https://docs.sui.io/concepts/sui-move-concepts/conventions

module oracle_sets::oracle_sets {
    
    public fun test_precision_loss(a: u64, b: u64): u64 {
        let c = a / b; // Precision loss here
        let d = c;
        let e = d * 10;
        e
    }

    // public fun test_bool_judgement(x: u8): bool {
    //     let is_equal = x == 0;
    //     let y = get_bool();
    //     is_equal == !y // Redundant comparison
    // }

    fun get_bool(): bool {
        false
    }

    // public fun test_const_judgement(account: &signer, n: u64): bool {
    //     let a = 10;
    //     let is_greater = a > 100; // Comparison with constant
    //     is_greater
    // }

    // public entry fun test_const_judgement_fp(account: &signer, n: u64) {
    //     let is_greater = n > 100; // Comparison with constant
    //     is_greater;
    // }

    // public entry fun test_infinite_loop(account: &signer, n: u64) {
    //     let i = 0;
    //     let sum = 0;
    //     while (i < n) {
    //         if (n > 1000) {
    //             sum = sum + i;
    //         }
    //     }
    // }

    // public fun test_infinite_loop_fp(account: &signer, n: u64, y: u64) {
    //     let i = 0;
    //     let sum = 0;
    //     if (n >= 0) {
    //         sum = sum + i;
    //         i = i + 1;
    //     }
    // }

}
