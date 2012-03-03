type t = {
    fd: Unix.fd;
    log: Olog.base_log;
    rng: Cryptokit.Random.rng;
    osel: Ounix.oselect;
    kex_methods: Kex.Methods.t list;
    mac_methods: Algorithms.MAC.t list;
    cipher_methods: Algorithms.Cipher.t list;
    hostkey_algorithms: Ssh_keys.PublicKey.t list;
    debugger: bool;  (* Is the SPL debugger active? *)
}

