open NetKAT_Types
open Optimize

module Tbl = Core.Std.Hashtbl.Poly

(* auxilliary list functions *)
let inters xs ys = List.find_all (fun x -> List.mem x ys) xs
let product xs ys =
  List.fold_right (fun x l -> List.fold_right (fun y l -> (x,y)::l) ys l) xs []
let minimize xs obj =
  let f best x =
    let v = obj x in
    match best with
    | None -> Some (x, v)
    | Some (y, v') -> if v<v' then Some (x, v) else best
  in
  List.fold_left f None xs

(* translate virtual fields to local fields *)
let rec devirtualize_pred pred =
  match pred with
  | True | False -> pred
  | Test (VSwitch vsw) -> Test (Local ("vsw", vsw))
  | Test (VPort vpt) ->  Test (Local ("vpt", vpt))
  | Test _ -> pred
  | And (a, b) -> And (devirtualize_pred a, devirtualize_pred b)
  | Or (a, b) -> Or (devirtualize_pred a, devirtualize_pred b)
  | Neg a -> Neg (devirtualize_pred a)

let rec devirtualize_pol pol =
  match pol with
  | Filter pred -> Filter (devirtualize_pred pred)
  | Mod (VSwitch vsw) -> Mod (Local ("vsw", vsw))
  | Mod (VPort vpt) ->  Mod (Local ("vpt", vpt))
  | Mod _ -> pol
  | Union (p, q) -> Union (devirtualize_pol p, devirtualize_pol q)
  | Seq (p, q) -> Seq (devirtualize_pol p, devirtualize_pol q)
  | Star p -> Star (devirtualize_pol p)
  | Link _ -> pol
  | VLink (vsw1, vpt1, vsw2, vpt2) ->
    let t1 = Test (VSwitch vsw1) in
    let t2 = Test (VPort vpt1) in
    let m1 = Mod (VSwitch vsw2) in
    let m2 = Mod (VPort vpt2) in
    let pol' = mk_big_seq [Filter (And (t1, t2)); m1; m2] in
    devirtualize_pol pol'


(* physical location *)
type ploc = switchId * portId

(* virtual location *)
type vloc = vswitchId * vportId

(* topology node *)
type ('a, 'b) node =
  | InPort of 'a * 'b
  | OutPort of 'a * 'b

(* extend ports with self-loops *)
type extendedPort =
  | RealPort of portId
  | Loop of portId (* when looping, remember last port! *)

(* virtual vertex *)
module VV = struct
  type t = (vswitchId, vportId) node
  let compare = compare
  let equal = (=)
  let hash  = Hashtbl.hash
end

(* physical vertex *)
module PV = struct
  type t = (switchId, extendedPort) node
  let compare = compare
  let equal = (=)
  let hash = Hashtbl.hash
end

(* product vertex *)
type product_vertex =
  | ConsistentIn of VV.t * PV.t
  | InconsistentOut of VV.t * PV.t
  | ConsistentOut of VV.t * PV.t
  | InconsistentIn of VV.t * PV.t
module V = struct
  type t = product_vertex
  let compare = compare
  let equal = (=)
  let hash = Hashtbl.hash
end



(* Module to build graphs from topologies (physical or virtual) *)
module GraphBuilder (Params : sig
  type switch
  type port
  val locs_from_pred : pred -> (switch * port) list
  val links_from_topo : policy -> (switch * port * switch * port) list
  val loop_of : port -> port
end) (Vlabel : Graph.Sig.COMPARABLE with type t = (Params.switch, Params.port) node) = struct
  include Params
  module G = Graph.Persistent.Digraph.Concrete(Vlabel)
  include G

  let add_vertex' v g = add_vertex g v
  let add_edge' v1 v2 g = add_edge g v1 v2

  let add_loc (sw, pt) g =
    let in_pt = G.V.create (InPort (sw, pt)) in
    let out_pt = G.V.create (OutPort (sw, pt)) in
    g |> add_vertex' in_pt
      |> add_vertex' out_pt

  let add_link (sw1, pt1, sw2, pt2) g =
    g |> add_loc (sw1, pt1)
      |> add_loc (sw2, pt2)
      |> add_edge' (G.V.create (OutPort (sw1, pt1))) (G.V.create (InPort (sw2, pt2)))

  let connect_switch_ports' v1 v2 g =
    match V.label v1, V.label v2 with
    | InPort (sw, _), OutPort (sw', _) when sw=sw' -> add_edge' v1 v2 g
    | _ -> g

  let connect_switch_ports g =
    fold_vertex (fun v1 g' -> fold_vertex (fun v2 g' -> connect_switch_ports' v1 v2 g') g g') g g

  let add_loop v g =
    match V.label v with
    | OutPort _ -> g
    | InPort (sw, pt) ->
       let inLoop = G.V.create (InPort (sw, loop_of pt)) in
       let outLoop = G.V.create (OutPort (sw, loop_of pt)) in
       g |> add_vertex' inLoop
         |> add_vertex' outLoop
         |> add_edge' inLoop outLoop
         |> add_edge' outLoop inLoop
         |> add_edge' v outLoop

  let make ?(with_loops=false) (ingress : pred) (egress : pred) (topo : policy) =
    G.empty |> List.fold_right add_link (links_from_topo topo)
            |> List.fold_right add_loc (locs_from_pred ingress)
            |> List.fold_right add_loc (locs_from_pred egress)
            |> (fun g -> if with_loops then fold_vertex add_loop g g else g)
            |> connect_switch_ports
end



(* Module holding the three types of graphs we need: virtual, phyiscal, and product graphs *)
module G = struct

  module Virt = GraphBuilder (struct
    type switch = vswitchId
    type port = vportId
    let rec locs_from_pred pred =
      match pred with
      | And (Test (VSwitch vsw), Test (VPort vpt)) -> [(vsw, vpt)]
      | Or (p1, p2) -> locs_from_pred p1 @ locs_from_pred p2
      | _ -> failwith "Virtual Compiler: not a valid virtual ingress/egress predicate"
    let rec links_from_topo vtopo =
      match vtopo with
      | VLink (vsw1,vpt1,vsw2,vpt2) -> [(vsw1,vpt1,vsw2,vpt2)]
      | Union (t1, t2) -> links_from_topo t1 @ links_from_topo t2
      | _ -> failwith "Virtual Compiler: not a valid virtual topology"
    let loop_of _ = assert false
  end) (VV)

  module Phys = GraphBuilder (struct
    type switch = switchId
    type port = extendedPort
    let rec locs_from_pred pred =
      match pred with
      | And (Test (Switch sw), Test (Location (Physical pt))) -> [(sw, RealPort pt)]
      | Or (p1, p2) -> locs_from_pred p1 @ locs_from_pred p2
      | _ -> failwith "Virtual Compiler: not a valid physical ingress/egress predicate"
    let rec links_from_topo topo =
      match topo with
      | Link (sw1,pt1,sw2,pt2) -> [(sw1, RealPort pt1, sw2, RealPort pt2)]
      | Union (t1, t2) -> links_from_topo t1 @ links_from_topo t2
      | _ -> failwith "Virtual Compiler: not a valid physical topology"

    let loop_of expt =
      match expt with
      | RealPort pt -> Loop pt
      | Loop _ -> assert false
  end) (PV)

  module Prod = Graph.Persistent.Digraph.Concrete(V)

end



let parse_vrel (vrel : pred) =
  let rec parse_physical pred alist =
    match pred with
    | Or (p1, p2) -> parse_physical p1 alist |> parse_physical p2
    | And (Test (Switch sw), Test (Location (Physical pt))) -> (sw, RealPort pt) :: alist
    | _ -> failwith "Virtual Compiler: not a valid virtual relation"
  in
  let rec parse pred alist =
    match pred with
    | Or (p1, p2) ->
       parse p1 alist |> parse p2
    | And (And (Test (VSwitch vsw), Test (VPort vpt)), physical) ->
       ((vsw, vpt), parse_physical physical []) :: alist
    | _ ->
       failwith "Virtual Compiler: not a valid virtual relation"
  in
  match Tbl.of_alist (parse vrel []) with
  | `Ok map -> map
  | `Duplicate_key (_, _) -> failwith "Virtual Compiler: virtual relation contains duplicate key"



let make_product_graph (vgraph : G.Virt.t) (pgraph : G.Phys.t) (ving : pred) (vrel : pred) =
begin

  let vrel_tbl = parse_vrel vrel in

  let vrel (vsw, vpt) = Tbl.find vrel_tbl (vsw, vpt) |> Core.Std.Option.value ~default:[] in

  let vrel' vv =
    match G.Virt.V.label vv with
    | InPort (vsw, vpt) ->
       vrel (vsw, vpt) |> List.map (fun (sw, pt) -> G.Phys.V.create (InPort (sw, pt)))
    | OutPort (vsw, vpt) ->
       vrel (vsw, vpt) |> List.map (fun (sw, pt) -> G.Phys.V.create (OutPort (sw, pt)))
  in

  let pgraph_closure =
    let module Op = Graph.Oper.P(G.Phys) in
    Op.transitive_closure ~reflexive:false pgraph
  in

  let virt_ing =
    List.map (fun (vsw, vpt) -> InPort (vsw, vpt) |> G.Virt.V.create) (G.Virt.locs_from_pred ving)
  in

  let prod_ing =
    List.map (fun vv -> product [vv] (vrel' vv)) virt_ing
    |> List.flatten
    |> List.map (fun (vv, pv) -> G.Prod.V.create (ConsistentIn (vv, pv)))
  in

  let step v =
    begin match G.Prod.V.label v with
    | ConsistentIn (vv, pv)  ->
       let virtual_sucs = G.Virt.succ vgraph vv in
       List.map (fun vv -> InconsistentOut (vv, pv) |> G.Prod.V.create) virtual_sucs
    | InconsistentOut (vv, pv) ->
       let physical_sucs =
         match vrel' vv with
         (* SJS: This is a hack. We interpret [] as true, although to be consistent we would have
                 to interpret it as false *)
         | [] -> G.Phys.succ pgraph_closure pv
         | logical_sucs -> inters logical_sucs (G.Phys.succ pgraph_closure pv) in
       List.map (fun psuc -> ConsistentOut (vv, psuc) |> G.Prod.V.create) physical_sucs
    | ConsistentOut (vv, pv) ->
       (* SJS: check that if there are no successors, we have reached the egress *)
       let virtual_sucs = G.Virt.succ vgraph vv in
       List.map (fun vsuc -> InconsistentIn (vsuc, pv) |> G.Prod.V.create) virtual_sucs
    | InconsistentIn (vv, pv) ->
       let physical_sucs =
         match vrel' vv with
         (* SJS: This is a hack. We interpret [] as true, although to be consistent we would have
                 to interpret it as false *)
         | [] -> G.Phys.succ pgraph_closure pv
         | logical_sucs -> inters logical_sucs (G.Phys.succ pgraph_closure pv) in
       List.map (fun pv -> ConsistentIn (vv, pv) |> G.Prod.V.create) physical_sucs
    end
  in

  let rec make work_list edges g =
    begin match work_list with
    | [] ->
       (* add edges after all vertices are inserted *)
       List.fold_left (fun g (v1, v2) -> G.Prod.add_edge g v1 v2) g edges
    | v::vs ->
       if G.Prod.mem_vertex g v then
         make vs edges g
       else
         let g' = G.Prod.add_vertex g v in
         let sucs = step v in
         let edges' = List.fold_left (fun edges suc -> (v, suc)::edges) edges sucs in
         make (sucs@work_list) edges' g'
    end
  in

  (prod_ing, make prod_ing [] (G.Prod.empty))

end



(* The fabric has to ensure that no matter what the programmer does, it can always restore
   consistency. This function eliminates all paths that allow the programmer to step to a
   unrepairable state. *)
let prune_product_graph g =
  (* an inconsistent location in the product graph is "fatal" if restoring consistency is
   impossible; here we exlude nodes that are fatal "by transitivity" *)
  let is_fatal v g =
    match G.Prod.V.label v with
    | InconsistentIn _ | InconsistentOut _ -> G.Prod.out_degree g v = 0
    | _ -> false
  in
  (* erases fatal node and all its predecessors that are fatal by transitivity *)
  let rec erase_fatal v g =
    match G.Prod.V.label v with
    | InconsistentIn _ | InconsistentOut _ ->
       let g' = G.Prod.remove_vertex g v in
       G.Prod.fold_pred erase_fatal g v g'
    | ConsistentOut _ | ConsistentIn _ ->
       let g' = G.Prod.remove_vertex g v in
       G.Prod.fold_pred (fun v g -> if is_fatal v g then erase_fatal v g else g) g v g'
  in
  G.Prod.fold_vertex (fun v g -> if is_fatal v g then erase_fatal v g else g) g g



(* The pruned graph may leave the fabric with several options to restore consistency; to arrive at
   a fabric graph, we must decide on a single option wherever we have a choice, thus determining a
   fabric uniquely.
   This function implements a greedy algorithm that makes this choice by minimizing the cost of the
   selection at each step, yielding a fabric valid for ingress ing. *)
let fabric_graph_of_pruned g ing cost =
  let rec select v g' =
    if G.Prod.mem_vertex g' v then g' else
    let g' = G.Prod.add_vertex g' v in
    match G.Prod.V.label v with
    | ConsistentIn _ | ConsistentOut _ ->
       G.Prod.fold_succ (select' v) g v g'
    | InconsistentIn _ | InconsistentOut _ ->
       let sucs = G.Prod.succ g v in
       begin match minimize sucs (fun v' -> cost v v') with
         | None -> assert false
         | Some (selection, _) -> select' v selection g'
       end
  and select' v v' g' =
    G.Prod.add_edge (select v' g') v v'
  in
  List.fold_right select ing G.Prod.empty



(* functions for fabric generation *)
let match_ploc (sw,pt) = Filter (And (Test(Switch sw), Test(Location(Physical(pt)))))
let match_vloc (vsw,vpt) = Filter (And (Test(VSwitch vsw), Test(VPort vpt)))
let set_vloc (vsw,vpt) = mk_seq (Mod (VSwitch vsw)) (Mod (VPort vpt))

let match_vloc' vv =
  match G.Virt.V.label vv with
  | InPort (vsw, vpt) | OutPort (vsw, vpt) -> match_vloc (vsw, vpt)

let match_ploc' pv =
  match G.Phys.V.label pv with
  | InPort (sw, RealPort pt) | OutPort (sw, RealPort pt)
  | InPort (sw, Loop pt) | OutPort (sw, Loop pt) -> match_ploc (sw, pt)

let set_vloc' vv =
  match G.Virt.V.label vv with
  | InPort (vsw, vpt) | OutPort (vsw, vpt) -> set_vloc (vsw, vpt)

let rec policy_of_path path =
  match path with
  | (OutPort (sw1, RealPort pt1), (InPort (sw2, RealPort pt2))) :: path' ->
     mk_seq (Link (sw1, pt1, sw2, pt2)) (policy_of_path path')
  | (OutPort (sw, Loop _), (InPort (sw', _))) :: path' ->
     assert (sw = sw');
     policy_of_path path'
  | (InPort (sw, _), (OutPort (sw', RealPort pt))) :: path' ->
     assert (sw = sw');
     mk_seq (Mod (Location (Physical (pt)))) (policy_of_path path')
  | (InPort (sw, _), (OutPort (sw', Loop _))) :: path' ->
     assert (sw = sw');
     policy_of_path path'
  | [] -> id
  | _ -> assert false

let fabric_atom_of_prod_edge path_oracle v1 v2 =
  match G.Prod.V.label v1, G.Prod.V.label v2 with
  | ConsistentOut _, InconsistentIn _ | ConsistentIn _, InconsistentOut _ -> `None
  | (InconsistentOut (vv, pv1) as l), ConsistentOut (vv', pv2)
  | (InconsistentIn (vv, pv1) as l), ConsistentIn (vv', pv2) ->
     assert (vv = vv');
     let path = path_oracle pv1 pv2 in
     let fabric = mk_big_seq [match_vloc' vv; match_ploc' pv1; policy_of_path path; set_vloc' vv] in
     begin match l with
       | InconsistentOut _ -> `Out fabric
       | InconsistentIn _ -> `In fabric
       | _ -> assert false
     end
  | _ -> assert false

let fabric_of_fabric_graph g ing path_oracle =
  if List.for_all (fun v -> G.Prod.mem_vertex g v) ing then
    let f v1 v2 ((fout, fin) as fs) =
      match fabric_atom_of_prod_edge path_oracle v1 v2 with
      | `None -> fs
      | `Out f -> (f::fout, fin)
      | `In f -> (fout, f::fin) in
    G.Prod.fold_edges f g ([], [])
  else
    failwith "global compiler: specification allows for no valid fabric"

let generate_fabrics vrel v_topo v_ing v_eg p_topo p_ing p_eg  =
  let module WEIGHT = struct
    type label = unit
    type t = int
    (* SJS: ideally, we should give loops weight 0, but this requires adding appropriate labels
       to the edges *)
    let weight _ = 1
    let compare = compare
    let add x y = x + y
    let zero = 0
  end in

  let vgraph = G.Virt.make v_ing v_eg v_topo in
  let pgraph = G.Phys.make ~with_loops:true p_ing p_eg p_topo in
  let prod_ing, prod_graph = make_product_graph vgraph pgraph v_ing vrel in

  let unwrap_e e = (G.Phys.V.label (G.Phys.E.src e), G.Phys.V.label (G.Phys.E.dst e)) in
  let unwrap_path path = List.map unwrap_e path in

  let module Dijkstra = Graph.Path.Dijkstra(G.Phys)(WEIGHT) in
  let dist_tbl = Tbl.create () in

  let get_path_and_distance pv1 pv2 =
    match Tbl.find dist_tbl (pv1, pv2) with
    | Some (path, dist) -> (path, dist)
    | None -> begin
      try
        let path', dist = Dijkstra.shortest_path pgraph pv1 pv2 in
        let path = unwrap_path path' in
        Tbl.replace dist_tbl ~key:(pv1, pv2) ~data:(path, dist);
        (path, dist)
      with Not_found ->
        assert false
    end
  in

  let path_oracle pv1 pv2 = fst (get_path_and_distance pv1 pv2) in

  let pv_of_v v =
    match G.Prod.V.label v with
    | InconsistentIn (_, pv) | InconsistentOut (_, pv)
    | ConsistentIn (_, pv) | ConsistentOut (_, pv) -> pv in

  let cost v1 v2 =
    snd (get_path_and_distance (pv_of_v v1) (pv_of_v v2)) in

  let pruned_graph = prune_product_graph prod_graph in
  let fabric_graph = fabric_graph_of_pruned pruned_graph prod_ing cost in
  let fabric = fabric_of_fabric_graph fabric_graph prod_ing path_oracle in
  begin
    Printf.printf "|V(vgraph)|: %i\n" (G.Virt.nb_vertex vgraph);
    Printf.printf "|E(vgraph)|: %i\n" (G.Virt.nb_edges vgraph);
    Printf.printf "|V(pgraph)|: %i\n" (G.Phys.nb_vertex pgraph);
    Printf.printf "|E(pgraph)|: %i\n" (G.Phys.nb_edges pgraph);
    Printf.printf "|V(prod_graph)|: %i\n" (G.Prod.nb_vertex prod_graph);
    Printf.printf "|E(prod_graph)|: %i\n" (G.Prod.nb_edges prod_graph);
    Printf.printf "|V(pruned_graph)|: %i\n" (G.Prod.nb_vertex pruned_graph);
    Printf.printf "|E(pruned_graph)|: %i\n" (G.Prod.nb_edges pruned_graph);
    Printf.printf "|V(fabric_graph)|: %i\n" (G.Prod.nb_vertex fabric_graph);
    Printf.printf "|E(fabric_graph)|: %i\n" (G.Prod.nb_edges fabric_graph);
    fabric
  end

(*
  Vingress defines the virtual ingress. Examples:

   1) The physical ingress is {(1,1)} (i.e. packets can enter the network only
      through port 1 of switch 1), and we want packets to enter the virtual network
      at vport 3 of vswitch 3. This is encoded as
        vingress =
          vswitch := 3; vport := 3

   2) The physical ingress is {(1,1), (2,2)} (i.e. packets can enter the network only
      through port 1 of switch 1 and port 2 of switch 2),
      and we want packets to enter the virtual network
      at vport 3 of vswitch 3. This is encoded as
        vingress =
          vswitch := 3; vport := 3

   3) The physical ingress is {(1,1)} and we want packets to enter the virtual network
      at both vport 3 of vswitch 3 and vport 4 of switch 4. This is encoded as
        vingress =
          (vswitch := 3; vport := 3) + (vswitch := 4; vport := 4)

   4) The physical ingress is {(1,1), (2,2)} and we want packets from (1,1) to
      enter the virtual network at vport 3 of vswitch 3, and packet from (2,2)
      shall enter at vport 4 of vswitch 4. This is encoded as
        vingress =
          switch = 1; port = 1; vswitch := 3; vport := 3
        + switch = 2; port = 2; vswitch := 4; vport := 4

   5) I just realized that the framework can even handle more complicated virtual ingress
      specifications as the ones Arjun mentioned in our last meeting, e.g.
        vingress =
          IPProto = tcp; vswitch := 1; vport := 1
        + IPProto = ucp; vswitch := 2; vport := 1
      This is super awesome!!


  To gurantee correctness we will have to do some sort of "type checking", i.e. we have to make sure
  certain pre conditions are met.

*)

let compile (vpolicy : policy) (vrel : pred)
  (vtopo : policy) (ving_pol : policy) (ving : pred) (veg : pred)
  (ptopo : policy)                     (ping : pred) (peg : pred) =
  let (fout_set, fin_set) = generate_fabrics vrel vtopo ving veg ptopo ping peg in
  let fout = mk_big_union fout_set in
  let fin = mk_big_union fin_set in
  let ing = mk_seq ving_pol (Filter ving) in
  let p = mk_seq vpolicy fout in
  let t = mk_seq vtopo fin in
  (* ing; (p;t)^*; p  *)
  Printf.printf "ing: %s\n" (NetKAT_Pretty.string_of_policy ing);
  Printf.printf "fout: %s\n" (NetKAT_Pretty.string_of_policy fout);
  Printf.printf "fin: %s\n" (NetKAT_Pretty.string_of_policy fin);
  Printf.printf "vpolicy: %s\n" (NetKAT_Pretty.string_of_policy vpolicy);
  Printf.printf "vtopo: %s\n" (NetKAT_Pretty.string_of_policy vtopo);
  devirtualize_pol (mk_big_seq [ing; mk_star (mk_seq p t); p])
  