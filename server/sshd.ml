(*
 * Copyright (c) 2005,2006 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Unix
open Ssh_utils
open Tty
open Printf

class mlsshd_config conf =
    let log = conf.Ssh_env_t.log in
    let rng = conf.Ssh_env_t.rng in
    let moduli_file = "./moduli" in
    let hostkey_file = "./server.rsa.key" in    
    let hostkey_size = 1024 in
    let rsa_hostkey =
            let fin = try open_in_bin hostkey_file
            with Sys_error x -> begin
                let keysize = hostkey_size in
                log#info (sprintf "Generating hostkey (%d bits)" keysize);
                let key = Cryptokit.RSA.new_key ~rng:rng keysize in
                let fout = open_out_bin hostkey_file in
                Marshal.to_channel fout key [];
                close_out fout;
                open_in_bin hostkey_file;
            end in
            let (key:Cryptokit.RSA.key) = Marshal.from_channel fin in
            close_in fin;
            key
    in
    object(self:#Ssh_config.server_config)

    val log = log
    
    (* Get server's private RSA key *)
    method get_rsa_key = rsa_hostkey

    (* Initialize a moduli file in OpenSSH format (normally /etc/moduli) *)
    method moduli_init =
        let primes = Kex.Methods.DHGex.empty_moduli () in
        try
            Ssh_openssh_formats.moduli moduli_file primes;
            primes;
        with Ssh_openssh_formats.Parse_failure ->
            (* Clear primes to be safe *)
            let primes = Kex.Methods.DHGex.empty_moduli () in
            let g1p,g1g = Kex.Methods.public_parameters Kex.Methods.DiffieHellmanGroup1SHA1 in
            let g14p,g14g = Kex.Methods.public_parameters Kex.Methods.DiffieHellmanGroup14SHA1 in
            Kex.Methods.DHGex.add_moduli ~primes ~size:1024l ~prime:g1p ~generator:g1g;
            Kex.Methods.DHGex.add_moduli ~primes ~size:2048l ~prime:g14p ~generator:g14g;
            primes

    (* Check to see if a banner should be displayed to the user at
       the beginning of authentication *)
    method auth_banner (user_name:string) =
        Some "Nex rules!!\n"

    (* Methods which must all succeed for successful authentication *)
    method auth_methods_supported : Userauth.t list =
        [Userauth.Public_key; Userauth.Password]
    
    (* Callback for password auth, also requests a public key auth *)
    method auth_password username password : bool * Userauth.t list =
        let _ = [Userauth.Public_key] in
        let x = [] in
        let _ = (username = "avsm" && password = "wibble"), x in
        true, x
    
    (* Callback for public key auth, always succeeds for now
       but also requests password auth *)
    method auth_public_key (user_name:string) (pubkey:Message.Key.o) =
        let x = if true then [] else [Userauth.Password] in
        true, x

    (* We dont care what the client says, just reply with our own
       window size for the moment *)
    method connection_request ws ps =
        Ssh_config.Server.Con_allow (131072l, 32768l)
    
    (* Not really used at the moment *)
    val conns = Hashtbl.create 1
    
    method connection_add (id:Channel.channel) =
        log#debug "new conn";
        Hashtbl.add conns id ();
        ()
        
    method connection_del (id:Channel.channel) =
        log#debug "conn del";
        Hashtbl.remove conns id;
        ()
    
    method connection_add_pty id modes (row,col,xpixel,ypixel) =
        let pty = Ounix.Pty.open_pty () in
        let tio = tcgetattr pty.Ounix.Pty.masterfd in
        Tty.parse_modes tio modes;
        tcsetattr pty.Ounix.Pty.masterfd TCSANOW tio;
        let pwin = {Ounix.Pty.row=row; col=col; xpixel=xpixel; ypixel=ypixel} in
        Some (pty, pwin)

    method connection_request_exec chan cmd =
        let pin_r, pin_w = pipe () in
        let pout_r, pout_w = pipe () in
        let perr_r, perr_w = pipe () in 
        let pid = fork () in
        if pid = 0 then begin
            let args = Array.of_list (Str.split (Str.regexp_string " ") cmd) in
            let dup2_and_close f1 f2 =
                dup2 f1 f2;
                close f1 in
            close pin_w;
            dup2_and_close pin_r stdin;
            close pout_r;
            dup2_and_close pout_w stdout;
            close perr_r;
            dup2_and_close perr_w stderr;
            (* stderr is now redirected, dont send debug messages any more! *)
            try execvp args.(0) args
            with Unix_error (x,s,y) -> begin
                print_endline (sprintf "%s: %s" y (error_message x));
                Pervasives.exit 1
            end
        end;
        List.iter close [pin_r; pout_w; perr_w];
        let stdin = Some pin_w in
        let stdout = Some pout_r in
        let stderr = Some perr_r in
        Some (pid, stdin, stdout, stderr)
    
    method connection_request_shell id = function
      |Some (pty, pty_window) ->
        let pid = fork () in
        if pid = 0 then begin
             close pty.Ounix.Pty.masterfd;
             Ounix.Pty.switch_controlling_pty pty;
             Ounix.Pty.window_size pty pty_window;
             dup2 pty.Ounix.Pty.slavefd stdin;
             dup2 pty.Ounix.Pty.slavefd stdout;
             dup2 pty.Ounix.Pty.slavefd stderr;
             close pty.Ounix.Pty.slavefd;
             let args = Array.make 1 "/bin/sh" in
             try execv "/bin/sh" args
             with Unix_error (x,s,y) -> begin
                print_endline (sprintf "%s: %s" y (error_message x));
                Pervasives.exit 1
            end
        end;
        (* XXX close pty.Ounix.Pty.slavefd in parent? probably - avsm *)
        (* Need to dup so we have two distinct fds to retrieve the appropriate
           session.  I think this isn't strictly needed any more, but just to be
           safe until all the 'channel sanity checks' for unique keys go in *)
        let stdin = Some (Unix.dup pty.Ounix.Pty.masterfd) in
        let stdout = Some (pty.Ounix.Pty.masterfd) in
        let (stderr:Unix.file_descr option) = None in
        Some (pid, stdin, stdout, stderr)
      |None ->
        self#connection_request_exec id "/bin/sh"
end

let start_server port log caller fd =
    let kex = [
        Kex.Methods.DiffieHellmanGexSHA1;
        Kex.Methods.DiffieHellmanGroup14SHA1;
        Kex.Methods.DiffieHellmanGroup1SHA1;
    ] in
    let macs = [
        Algorithms.MAC.SHA1;
        Algorithms.MAC.SHA1_96;
        Algorithms.MAC.MD5;
        Algorithms.MAC.MD5_96;
    ] in
    let ciphers = [
        Algorithms.Cipher.AES_256_CBC;
        Algorithms.Cipher.AES_192_CBC;
        Algorithms.Cipher.AES_128_CBC;
        Algorithms.Cipher.Arcfour;
        Algorithms.Cipher.TripleDES_CBC;
    ] in
    let host_key_algorithms = [
        Keys.PublicKey.RSAKey
    ] in
    let osel = new Ounix.oselect in
    let osig = new Ounix.osignal in
    let conf = {
        Ssh_env_t.fd = new Ounix.tcp_odescr fd;
        log = log;
        rng = Cryptokit.Random.device_rng "/dev/urandom";
        kex_methods = kex;
        mac_methods = macs;
        cipher_methods = ciphers;
        hostkey_algorithms = host_key_algorithms;
        osel = osel;
    } in
    let server_conf = new mlsshd_config conf in
    let env = new Ssh_server.env conf (server_conf:>Ssh_config.server_config) in
    osel#add_ofd (env#get_ofd :> Ounix.odescr);    
    osig#add_sigchld_handler (fun () ->
        let retry = ref true in
        try while !retry do
            let pid, status = waitpid [WNOHANG] (-1) in
            retry := false;
            if pid <> 0 then begin
                umay (fun (chan:Channel.channel) ->
                    chan#clear_pid;
                    let _ = match status with
                    |WEXITED s -> chan#set_exit_status s
                    |_ -> () in
                    env#close_channel chan) (env#chans#find_by_pid pid);
            end
        done with Unix_error (err, _, _) as p -> begin
            match err with
            |EINTR -> ()
            |ECHILD -> ()
            |_ -> raise p
        end
    );
    while env#connection_active do
        osel#read;
        osig#process;
        env#reset;
    done;
    log#debug "new_ssh_connection ended";
    exit 1
    
let _ =
    let port = 2222 in
    let sock = ADDR_INET (inet_addr_any, port) in
    let log = new Olog.stderr_log in
    log#init;
    log#set_debug;
    let sfun = Server.handle_single log (start_server port) in
    try
    Server.establish_server log sfun sock
    with
    |Cryptokit.Error x ->
        log#critical (string_of_cryptokit_error x);
        Pervasives.exit 1 
    |Unix.Unix_error (x,s,y) ->
        log#critical (sprintf "%s: %s: %s" s y (Unix.error_message x));
        Pervasives.exit 1
