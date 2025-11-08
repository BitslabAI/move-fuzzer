
<a id="0x0_math_u256"></a>

# Module `0x0::math_u256`



-  [Constants](#@Constants_0)
-  [Function `div_mod`](#0x0_math_u256_div_mod)
-  [Function `shlw`](#0x0_math_u256_shlw)
-  [Function `shrw`](#0x0_math_u256_shrw)
-  [Function `checked_shlw`](#0x0_math_u256_checked_shlw)
-  [Function `div_round`](#0x0_math_u256_div_round)
-  [Function `add_check`](#0x0_math_u256_add_check)


<pre><code></code></pre>



<a id="@Constants_0"></a>

## Constants


<a id="0x0_math_u256_MAX_U256"></a>



<pre><code><b>const</b> <a href="overflow.md#0x0_math_u256_MAX_U256">MAX_U256</a>: u256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
</code></pre>



<a id="0x0_math_u256_div_mod"></a>

## Function `div_mod`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_div_mod">div_mod</a>(num: u256, denom: u256): (u256, u256)
</code></pre>



<a id="0x0_math_u256_shlw"></a>

## Function `shlw`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_shlw">shlw</a>(n: u256): u256
</code></pre>



<a id="0x0_math_u256_shrw"></a>

## Function `shrw`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_shrw">shrw</a>(n: u256): u256
</code></pre>



<a id="0x0_math_u256_checked_shlw"></a>

## Function `checked_shlw`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_checked_shlw">checked_shlw</a>(n: u256): (u256, bool)
</code></pre>



<a id="0x0_math_u256_div_round"></a>

## Function `div_round`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_div_round">div_round</a>(num: u256, denom: u256, round_up: bool): u256
</code></pre>



<a id="0x0_math_u256_add_check"></a>

## Function `add_check`



<pre><code><b>public</b> <b>fun</b> <a href="overflow.md#0x0_math_u256_add_check">add_check</a>(num1: u256, num2: u256): bool
</code></pre>
