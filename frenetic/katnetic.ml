module Run = struct
  open Core.Std
  open Async.Std

  let main update learn no_discovery no_host policy_queue_size filename =
    let main () =
      let open Async_NetKAT in
      let static = match filename with
      | None   -> Policy.create_from_string "filter true"
      | Some f -> Policy.create_from_file f
      in
      let host      = not (no_host) in
      let discovery = not (no_discovery) in
      let app = if learn
        then seq static (Learning.create ())
        else static
      in
      let open Async_NetKAT_Controller in
      start ~update ?policy_queue_size app ()
      >>= (fun t ->
        begin if host then enable_host_discovery t else return () end >>= fun () ->
        begin if discovery then enable_discovery t else return () end)
      >>> fun () -> ()
    in
    never_returns (Scheduler.go_main ~max_num_open_file_descrs:4096 ~main ())
end

module Global = struct
  let main ingress_file egress_file policy_file =
    let fmt = Format.formatter_of_out_channel stderr in
    let () = Format.pp_set_margin fmt 120 in
    let ingress =
      Core.Std.In_channel.with_file ingress_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let egress =
      Core.Std.In_channel.with_file egress_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let global_pol =
      Core.Std.In_channel.with_file policy_file ~f:(fun chan ->
        NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let local_pol = NetKAT_GlobalCompiler.compile ingress egress global_pol in
    let switches =
      NetKAT_Misc.switches_of_policy (Optimize.mk_seq (NetKAT_Types.Filter ingress) global_pol) in
    let tables =
      List.map
        (fun sw -> NetKAT_LocalCompiler.compile local_pol
                   |> NetKAT_LocalCompiler.to_table sw
                   |> (fun t -> (sw, t)))
        switches in
    let print_table (sw, t) =
      Format.fprintf fmt "[global] Flowtable for Switch %Ld:@\n@[%a@]@\n@\n"
        sw
        SDN_Types.format_flowTable t in
    Format.fprintf fmt "@\n";
    Format.fprintf fmt "[global] Ingress:@\n@[%a@]@\n@\n" NetKAT_Pretty.format_pred ingress;
    Format.fprintf fmt "[global] Egress:@\n@[%a@]@\n@\n" NetKAT_Pretty.format_pred egress;
    Format.fprintf fmt "[global] Input Policy:@\n@[%a@]@\n@\n" NetKAT_Pretty.format_policy global_pol;
    Format.fprintf fmt "[global] CPS Policy:@\n@[%a@]@\n@\n" NetKAT_Pretty.format_policy local_pol;
    List.iter print_table tables;
    ()
end

module Virtual = struct
  let main vpolicy_file vrel_file vtopo_file ving_pol_file ving_file veg_file
                                  ptopo_file               ping_file peg_file =
    let fmt = Format.formatter_of_out_channel stderr in
    let () = Format.pp_set_margin fmt 120 in
    let vpolicy =
      Core.Std.In_channel.with_file vpolicy_file ~f:(fun chan ->
        NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let vrel =
      Core.Std.In_channel.with_file vrel_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let vtopo =
      Core.Std.In_channel.with_file vtopo_file ~f:(fun chan ->
        NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let ving_pol =
      Core.Std.In_channel.with_file ving_pol_file ~f:(fun chan ->
        NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let ving =
      Core.Std.In_channel.with_file ving_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let veg =
      Core.Std.In_channel.with_file veg_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let ptopo =
      Core.Std.In_channel.with_file ptopo_file ~f:(fun chan ->
        NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let ping =
      Core.Std.In_channel.with_file ping_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let peg =
      Core.Std.In_channel.with_file peg_file ~f:(fun chan ->
        NetKAT_Parser.pred_program NetKAT_Lexer.token (Lexing.from_channel chan)) in
    let global_physical_pol =
      NetKAT_VirtualCompiler.compile vpolicy vrel vtopo ving_pol ving veg ptopo ping peg in
    let local_physical_pol =
      NetKAT_GlobalCompiler.compile ping peg global_physical_pol in
    let print_table (sw, t) =
      Format.fprintf fmt "[global] Flowtable for Switch %Ld:@\n@[%a@]@\n@\n"
        sw
        SDN_Types.format_flowTable t in
    let _ = begin
    Format.fprintf fmt "@\n[global] Parsed: @[%s@] @[%s@] @[%s@] @[%s@] @[%s@] @[%s@] @[%s@] @[%s@] @[%s@] @\n@\n"
      vpolicy_file vrel_file vtopo_file ving_pol_file ving_file veg_file ptopo_file ping_file peg_file;
    Format.fprintf fmt "[global] Global Policy:@\n@[%a@]@\n@\n"
      NetKAT_Pretty.format_policy global_physical_pol;
    Format.fprintf fmt "[global] CPS Policy:@\n@[%a@]@\n@\n"
      NetKAT_Pretty.format_policy local_physical_pol
    end in
    let compiled_physical_pol = NetKAT_LocalCompiler.compile local_physical_pol in
    let switches = NetKAT_Misc.switches_of_policy
      (Optimize.mk_seq (NetKAT_Types.Filter ping) global_physical_pol) in
    let tables =
      List.map (fun sw -> (sw, NetKAT_LocalCompiler.to_table sw compiled_physical_pol)) switches in
    Format.fprintf fmt "[global] Localized CPS Policies:@\n@\n";
    List.iter print_table tables;
    ()
end

module Dump = struct
  open Core.Std
  open Async.Std

  type level = All | Policies | Flowtables | Stats

  let with_channel f chan =
    f (NetKAT_Parser.program NetKAT_Lexer.token (Lexing.from_channel chan))

  let with_file f filename =
    In_channel.with_file filename ~f:(with_channel f)

  let profile f =
    let t1 = Unix.gettimeofday () in
    let r = f () in
    let t2 = Unix.gettimeofday () in
    (t2 -. t1, r)

  module Local = struct

    let with_compile p =
      let open NetKAT_LocalCompiler in
      let _ = Format.printf "@[Compiling policy [size=%d]...@]%!"
        (NetKAT_Semantics.size p)
      in
      let c_time, i = profile (fun () -> compile p) in
      let _ = Format.printf "@[Done [ctime=%fs dsize=%d]@\n@]%!"
        c_time (size i)
      in
      i

    let with_generate (sw : SDN_Types.switchId) i =
      let open NetKAT_LocalCompiler in
      let _ = Format.printf "@[Generating table for switch %Ld...@]%!" sw in
      let t_time, t = profile (fun () -> to_table sw i) in
      let _ = Format.printf "@[Done [ttime=%fs tsize=%d]@\n@]%!"
        t_time (List.length t) in
      t

    let flowtable (sw : SDN_Types.switchId) t =
      if List.length t > 0 then
        Format.printf "@[flowtable for switch %Ld:@\n%a@\n@\n@]%!"
          sw
          SDN_Types.format_flowTable t

    let policy p =
      Format.printf "@[%a@\n@\n@]%!" NetKAT_Pretty.format_policy p

    let local f num_switches p =
      let i = with_compile p in
      let rec loop switch_id =
        if switch_id > num_switches then ()
        else begin
          let t = with_generate switch_id i in
          f switch_id t; loop Int64.(switch_id + 1L)
        end
      in
      loop 0L

    let all sw_num p =
      policy p;
      local flowtable sw_num p

    let stats sw_num p =
      local (fun x y -> ()) sw_num p

    let main level num_switches filename =
      Format.set_margin 200;
      match level with
        | All -> with_file (all num_switches) filename
        | Policies -> with_file policy filename
        | Flowtables -> with_file (local flowtable num_switches) filename
        | Stats -> with_file (stats num_switches) filename
  end
end

open Cmdliner

let run_cmd : unit Cmdliner.Term.t * Cmdliner.Term.info =
  let update =
    let strategy = Arg.enum
      [ ("best-effort", `BestEffort)
      ; ("per-packet-consistent", `PerPacketConsistent) ] in

    let doc = "specify network strategy. $(docv) can either be
    `per-packet-consistent' or `best-effort', which provides no consistentcy
    guarentees." in
    Arg.(value & opt strategy `BestEffort & info ["update"] ~docv:"STRATEGY" ~doc)
  in
  let learn =
    let doc = "enable per-switch L2 learning" in
    Arg.(value & flag & info ["learn"] ~doc)
  in
  let no_discovery =
    let doc = "disable topology and host discovery" in
    Arg.(value & flag & info ["disable-discovery"] ~doc)
  in
  let no_host =
    let doc = "disable host discovery" in
    Arg.(value & flag & info ["disable-host-discovery"] ~doc)
  in
  let policy =
    let doc = "file containing a static NetKAT policy" in
    Arg.(value & (pos 0 (some file) None) & info [] ~docv:"FILE" ~doc)
  in
  let policy_queue_size =
    let doc = "maximum number of policies to queue before the controller
    modifies the network" in
    Arg.(value & opt (some int) None & info ["policy-queue-size"] ~docv:"SIZE" ~doc)
  in
  let doc = "start a controller that will serve the static policy" in
  Term.(pure Run.main $ update $ learn $ no_discovery $ no_host $ policy_queue_size $ policy),
  Term.info "run" ~doc

let dump_cmd : unit Cmdliner.Term.t * Cmdliner.Term.info =
  let doc = "dump per-switch compiler results and statistics" in
  let switch_id =
    let doc = "the maximum switch id in the policy" in
    Arg.(required & (pos 0 (some int64) None) & info [] ~docv:"NUM_SWITCHES" ~doc)
  in
  let level =
    let doc = "Dump all compiler information (default)" in
    let all = Dump.All, Arg.info ["all"] ~doc in

    let doc = "Dump per-switch policy" in
    let policies = Dump.Policies, Arg.info ["policies"] ~doc in

    let doc = "Dump per-switch flowtables" in
    let flowtables = Dump.Flowtables, Arg.info ["flowtables"] ~doc in

    let doc = "Dump per-switch profiling statistics" in
    let stats = Dump.Stats, Arg.info ["stats"] ~doc in

    Arg.(last & vflag_all [Dump.All] [all;policies;flowtables;stats])
  in
  let policy =
    let doc = "file containing a static NetKAT policy" in
    Arg.(required & (pos 1 (some file) None) & info [] ~docv:"FILE" ~doc)
  in

  Term.(pure Dump.Local.main $ level $ switch_id $ policy),
  Term.info "dump" ~doc

let global_cmd : unit Cmdliner.Term.t * Cmdliner.Term.info =
  let doc = "invoke the global compiler and dump the resulting flow tables" in
  let ingress_file =
    let doc = "file containing a NetKAT predicate" in
    Arg.(required & (pos 0 (some file) None) & info [] ~docv:"INGRESS" ~doc)
  in
  let egress_file =
    let doc = "file containing a NetKAT predicate" in
    Arg.(required & (pos 1 (some file) None) & info [] ~docv:"EGRESS" ~doc)
  in
  let policy_file =
    let doc = "file containing a static global NetKAT policy" in
    Arg.(required & (pos 2 (some file) None) & info [] ~docv:"POLICY" ~doc)
  in
  Term.(pure Global.main $ ingress_file $ egress_file $ policy_file),
  Term.info "global" ~doc

let virtual_cmd : unit Cmdliner.Term.t * Cmdliner.Term.info =
  let doc = "invoke the virtual compiler and dump the resulting flow tables" in
  let vpolicy =
    let doc = "file containing the local virtual policy (containing no links)" in
    Arg.(required & (pos 0 (some file) None) & info [] ~docv:"VPOLICY" ~doc)
  in
  let vrel =
    let doc = "file containing the virtual relation" in
    Arg.(required & (pos 1 (some file) None) & info [] ~docv:"VREL" ~doc)
  in
  let vtopo =
    let doc = "file containing the virtual topology" in
    Arg.(required & (pos 2 (some file) None) & info [] ~docv:"VTOPO" ~doc)
  in
  let ving_pol =
    let doc = "file containing the virtual ingress policy" in
    Arg.(required & (pos 3 (some file) None) & info [] ~docv:"VINGRESSPOL" ~doc)
  in
  let ving =
    let doc = "file containing the virtual ingress predicate" in
    Arg.(required & (pos 4 (some file) None) & info [] ~docv:"VINGRESS" ~doc)
  in
  let veg =
    let doc = "file containing the virtual eggress predicate" in
    Arg.(required & (pos 5 (some file) None) & info [] ~docv:"VINGRESS" ~doc)
  in
  let ptopo =
    let doc = "file containing the virtual topology" in
    Arg.(required & (pos 6 (some file) None) & info [] ~docv:"PTOPO" ~doc)
  in
  let ping =
    let doc = "file containing the virtual ingress predicate" in
    Arg.(required & (pos 7 (some file) None) & info [] ~docv:"PINGRESS" ~doc)
  in
  let peg =
    let doc = "file containing the virtual eggress predicate" in
    Arg.(required & (pos 8 (some file) None) & info [] ~docv:"PEGRESS" ~doc)
  in
  Term.(pure Virtual.main $ vpolicy $ vrel $ vtopo $ ving_pol $ ving $ veg $ ptopo $ ping $ peg),
  Term.info "virtual" ~doc

let default_cmd : unit Cmdliner.Term.t * Cmdliner.Term.info =
  let doc = "an sdn controller platform" in
  Term.(ret (pure (`Help(`Plain, None)))),
  Term.info "katnetic" ~version:"1.6.1" ~doc

let cmds = [run_cmd; dump_cmd; global_cmd; virtual_cmd]

let () = match Term.eval_choice default_cmd cmds with
  | `Error _ -> exit 1 | _ -> exit 0
