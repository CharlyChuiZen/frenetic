open NetKAT_Types

type explicit_topo_policy =
  | Filter of pred
  | Mod of SDN_Types.field * header_val
      (* switch, port -> switch, port *)
  | Link of header_val*header_val*header_val*header_val
  | Par of explicit_topo_policy * explicit_topo_policy
  | Seq of explicit_topo_policy * explicit_topo_policy
  | Star of explicit_topo_policy

(* i;(p;t)^*;e 
   where 
   i = t = v | h = v | t <- v | i + i | i ; i
   p = t = v | h = v | t <- v | h <- v | p + p | p ; p | p*
   t = sw = v | p = v | sw <- v | p <- v | t + t
   e = i
*)

type restricted_header = 
  | PHeader of SDN_Types.field
  | VHeader of int * int

type header_pred = 
  | HTrue
  | HFalse
  | HTest of restricted_header * header_val
  | HTTest of header_val
  | HNeg of header_pred
  | HAnd of header_pred * header_pred
  | HOr of header_pred * header_pred

type ingress_pol =
  | IFilter of header_pred
  | IMod of restricted_header * header_val
  | IPar of ingress_pol * ingress_pol
  | ISeq of ingress_pol * ingress_pol
  | IPass
  | IDrop

type switch_pol =
  | SFilter of header_pred
  | SMod of restricted_header * header_val
  | SPar of switch_pol * switch_pol
  | SSeq of switch_pol * switch_pol
  | SStar of switch_pol
  | SPass
  | SDrop

type topo_header =
  | TSwitch
  | TPort

type topo_pol = 
  | TTest of topo_header * header_val
  | TMod of topo_header * header_val
  | TPar of topo_pol * topo_pol
  | TSeq of topo_pol * topo_pol
  | TDrop

type restricted_pol = ingress_pol * switch_pol * topo_pol * ingress_pol

let vheader_count = ref 0

let gen_header size =
  incr vheader_count;
  VHeader(!vheader_count, size)

let rec pred_to_ipred pr = 
  match pr with
  | True -> HTrue
  | False -> HFalse
  | Test (Switch, v) -> HTTest(v)
  | Test (Header h, v) -> HTest (PHeader h, v)
  | Neg p -> HNeg (pred_to_ipred p)
  | And(a,b) -> HAnd (pred_to_ipred a, pred_to_ipred b)
  | Or(a,b) -> HOr (pred_to_ipred a, pred_to_ipred b)

(* Compilation story: we have an unlimited number of header fields we
   can allocate on demand. Each header field has a specific number of
   entries. At a later stage, we inject the multiple header fields into a
   single header that allows arbitrary bitmasking. There should be some
   analysis/optimizations we can do (ala the earlier slices compiler) to
   reduce the number of unique entries required.

   Alternatively, lacking a bitmaskable field, we could simply expand
   all possible combinations of values and match/set them
   appropriately. We'd need some pretty good analysis to keep this
   from exploding.
*)
let rec dehopify (p : explicit_topo_policy) : restricted_pol =
  match p with
    | Filter pr -> IFilter (pred_to_ipred pr), SDrop, TDrop, IPass
    | Mod (h, v) -> IMod (PHeader h, v), SDrop, TDrop, IPass
    | Link (sw1,p1,sw2,p2) -> 
      IPass, 
      SPass, 
      TSeq(TTest (TSwitch, sw1), 
	   TSeq( TTest (TPort, p1), 
		 TSeq (TMod (TSwitch, sw2),  
		       TMod (TPort, p2)))), 
      IPass
    (* Todo: add topo filter terms *)
    | Par (p,q) -> let i_p,s_p,t_p,e_p = dehopify p in
                   let i_q,s_q,t_q,e_q = dehopify q in
                   let h = gen_header 6 in
                   let h0 = VInt.Int16 0 in
                   (ignore h0);
                   let h1 = VInt.Int16 1 in
                   let h2 = VInt.Int16 2 in
                   let h3 = VInt.Int16 3 in
                   (ignore h3);
                   let h4 = VInt.Int16 4 in
                   let h5 = VInt.Int16 5 in
                   (IPar(
                     IPar(
                       IPar(ISeq(i_p, IMod (h,h1)), ISeq(i_p, IMod(h,h2))), 
                       ISeq(i_q, IMod(h, h4))), 
                     ISeq(i_q, IMod(h,h5))),
		    SPar(SSeq(SFilter(HTest(h,h1)), s_p), 
                         SPar(SSeq(SFilter(HTest(h, h1)), 
                                   SSeq(s_p, SMod(h,h2))), 
                              SPar(SSeq(SFilter(HTest(h,h4)), s_q), 
                                   SSeq(SFilter(HTest(h,h4)), SSeq(s_q, SMod(h,h5)))))),
                    TPar(t_p,t_q),
                    IPar(ISeq(IFilter(HTest(h,h2)), e_p),
                         ISeq(IFilter(HTest(h, h5)), e_q)))
    | _ -> 
      failwith "Unimplemented" 


module Local = struct
(* metavariable conventions
   - a, b, c, actions
   - s, t, u, action sets
   - x, y, z, patterns
   - xs, ys, zs, pattern sets
   - p, q, local
   - r, atoms
*)

  module K = NetKAT_Types

  exception Empty_pat

(* Patterns *)
  type pat = K.header_val_map 

  type act = K.header_val_map 

  module PatSet = Set.Make(struct
    type t = pat 
    let compare = K.HeaderMap.compare Pervasives.compare
  end)

  module ActSet = Set.Make (struct
    type t = act
    let compare = K.HeaderMap.compare Pervasives.compare
  end)

  type acts = ActSet.t

  type atom = PatSet.t * pat

(* constants *)
  let tru : pat = K.HeaderMap.empty

  let is_tru (x:pat) : bool = K.HeaderMap.is_empty x

  let fls : atom = (PatSet.singleton tru,tru) 

  let rec pat_matches (h:K.header) (v:K.header_val) (x:pat) : bool =
    not (K.HeaderMap.mem h x) || K.HeaderMap.find h x = v

(* operations *)
  let apply_act_pat (a:act) (x:pat) = 
    let f h vo1 vo2 = match vo1,vo2 with 
      | _, Some v2 -> 
        Some v2
      | _ -> 
        vo1 in 
    K.HeaderMap.merge f a x 

  let apply_act_atom (a:act) ((xs,x):atom) : atom = 
    let x' = apply_act_pat a x in 
    (PatSet.remove x' xs, x')

  let rec seq_pat_pat (x : pat) (y : pat) : pat option =
    let f h vo1 vo2 = match vo1, vo2 with
      | (Some v1, Some v2) ->
        if v1 <> v2 then raise Empty_pat else Some v1
      | (Some v1, None) ->
        Some v1
      | (None, Some v2) ->
        Some v2
      | (None, None) ->
        None in
    try
      Some (K.HeaderMap.merge f x y)
    with
          Empty_pat -> None

  let rec seq_pat_act_pat (x : pat) (a:act) (y : pat) : pat option =
    let f h vo1 vo2 = match vo1, vo2 with
      | Some (vo11, Some v12), Some v2 ->
        if v12 <> v2 then raise Empty_pat else vo11
      | Some (vo11, Some v12), None -> 
        vo11 
      | Some (Some v11, None), Some v2 -> 
        if v11 <> v2 then raise Empty_pat else Some v11
      | Some (Some v11, None), None ->
        Some v11
      | _, Some v2 -> 
        Some v2
      | _, None ->
        None in 
    let g h vo1 vo2 = Some (vo1, vo2) in 
    try
      Some (K.HeaderMap.merge f 
              (K.HeaderMap.merge g x a) y)
    with
          Empty_pat -> None

  let rec seq_act_act (a:act) (b:act) : act =
    let f h vo1 vo2 = match vo1, vo2 with
      | (_, Some v2) ->
        Some v2
      | _ -> 
        vo1 in
    K.HeaderMap.merge f a b

  let check_atom ((xs,x) as r) = 
    if PatSet.mem x xs then 
      None
    else 
      Some r

  let seq_atom_atom (xs1,x1) (xs2,x2) = 
    match seq_pat_pat x1 x2 with 
      | Some x12 -> 
        check_atom (PatSet.union xs1 xs2, x12)
      | None -> 
        None

  let seq_atom_act_atom (xs1,x1) a (xs2,x2) = 
    match seq_pat_act_pat x1 a x2 with 
      | Some x12 -> 
        check_atom (PatSet.union xs1 xs2, x12)
      | None -> 
        None       
          
  let id : act = K.HeaderMap.empty

(* there is only one element, and it is the empty sequence of updates *)
  let is_id (pol : acts) : bool =
    not (ActSet.is_empty pol) && K.HeaderMap.is_empty (ActSet.choose pol)

  let drop : acts = ActSet.empty

  let is_drop (s : acts) : bool = ActSet.is_empty s

(* Local *)
  module Local = Map.Make (struct
    type t = atom 
    let compare (xs1,x1) (xs2,x2) = 
      if PatSet.mem x2 xs1 then 1
      else if PatSet.mem x1 xs2 then -1
      else 
        let cmp1 = PatSet.compare xs1 xs2 in 
        if cmp1 = 0 then 
          K.HeaderMap.compare Pervasives.compare x1 x2 
        else
          cmp1
  end)

  type local = acts Local.t

(* ugly printing *)
  let header_val_map_to_string eq sep m =
    K.HeaderMap.fold
      (fun h v acc ->
        Printf.sprintf "%s%s%s%s"
	  (if acc = "" then "" else acc ^ sep)
	  (K.string_of_header h)
	  eq
	  (K.string_of_vint v))
      m ""

  let pat_to_string pt =
    if K.HeaderMap.is_empty pt then "true"
    else Printf.sprintf "%s" (header_val_map_to_string "=" ", " pt)

  let pats_to_string xss =
    Printf.sprintf "{%s}"
      (PatSet.fold
         (fun x acc -> pat_to_string x ^ if acc = "" then "" else ", " ^ acc)
         xss "")

  let act_to_string a =
    if K.HeaderMap.is_empty a then "id"
    else Printf.sprintf "%s" (header_val_map_to_string ":=" "; " a)

  let acts_to_string s =
    Printf.sprintf "{%s}"
      (ActSet.fold
         (fun a acc -> act_to_string a ^ if acc = "" then "" else ", " ^ acc)
         s "")

  let atom_to_string (xs,x) = 
    Printf.sprintf "%s,%s" 
      (pats_to_string xs) (pat_to_string x)

  let to_string (p:local) =
    Local.fold
      (fun r s acc -> 
        Printf.sprintf "%s(%s) => %s\n"
          (if acc = "" then "" else "" ^ acc)
          (atom_to_string r) (acts_to_string s))
      p ""

(* Compiler operations *)
  let extend (r:atom) (s:acts) (p:local) : local = 
    let (xs,x) = r in 
    if PatSet.mem tru xs || PatSet.mem x xs then 
      p
    else if Local.mem r p then 
      Local.add r (ActSet.union s (Local.find r p)) p
    else
      Local.add r s p

  let rec par_local_local (p:local) (q:local) : local =
    let diff_atoms (xs1,x1) (xs2,x2) s1 p = 
      PatSet.fold 
        (fun x2i acc -> 
          match seq_pat_pat x1 x2i with 
            | None -> acc
            | Some x12i -> extend (xs1,x12i) s1 acc) 
        xs2 (extend (PatSet.add x2 xs1, x1) s1 p) in 
    Local.fold (fun ((xs1,x1) as r1) s1 acc -> 
      Local.fold (fun ((xs2,x2) as r2) s2 acc -> 
        match seq_atom_atom r1 r2 with 
          | None -> 
            extend r1 s1 (extend r2 s2 acc)
          | Some r12 -> 
            extend r12 (ActSet.union s1 s2)
              (negate_atoms r1 r2 s1
                 (negate_atoms r2 r1 s2 acc)))
        p acc)
      q Local.empty

  let seq_act_acts (a:act) (s:acts) = 
    ActSet.fold 
      (fun b acc -> ActSet.add (seq_act_act a b) acc) 
      s ActSet.empty

  let seq_atom_act_local (r1:atom) (a:act) (p2:local) (q:local) : local = 
    Local.fold
      (fun r2 s2 acc -> 
        match seq_atom_act_atom r1 a r2 with
          | None -> 
            acc
          | Some r12 -> 
            extend r12 (seq_act_acts a s2) acc)
      p2 q

  let seq_local_local (p:local) (q:local) : local = 
    Local.fold
      (fun r1 s1 acc -> 
        if ActSet.is_empty s1 then 
          extend r1 s1 acc 
        else
          ActSet.fold 
            (fun a acc -> seq_atom_act_local r1 a q acc)
            s1 acc)
      p Local.empty

  let negate (p:local) : local = 
    Local.fold
      (fun r s acc -> 
        if ActSet.is_empty s then 
          Local.add r (ActSet.singleton id) acc
        else
          Local.add r ActSet.empty acc)
      p Local.empty

  let rec pred_local (pr : K.pred) : local = 
    match pr with
      | K.True ->
        Local.singleton (PatSet.empty, tru) (ActSet.singleton id)
      | K.False ->
        Local.singleton (PatSet.empty, tru) ActSet.empty
      | K.Neg p ->
        negate (pred_local p)
      | K.Test (h, v) ->
        let p = K.HeaderMap.singleton h v in 
        Local.add (PatSet.empty, p) (ActSet.singleton id)
          (Local.singleton (PatSet.singleton p, tru) ActSet.empty)
      | K.And (pr1, pr2) ->
        seq_local_local (pred_local pr1) (pred_local pr2)
      | K.Or (pr1, pr2) ->
        par_local_local (pred_local pr1) (pred_local pr2)

  let star_local (p:local) : local =
    let rec loop (acc:local) : local =
      let seq' = seq_local_local acc p in
      let acc' = par_local_local acc seq' in
      if Local.compare ActSet.compare acc acc' = 0 then
        acc
      else 
        loop acc' in
    loop (Local.add (PatSet.empty, tru) (ActSet.singleton id) Local.empty)

  let rec local_normalize (pol : K.policy) : local = match pol with
    | K.Filter pr ->
      pred_local pr
    | K.Mod (K.Switch, _) ->
      failwith "unexpected Switch in local_normalize"
    | K.Mod (h, v) ->
      Local.singleton (PatSet.empty, tru) (ActSet.singleton (K.HeaderMap.singleton h v))
    | K.Par (pol1, pol2) ->
      par_local_local (local_normalize pol1) (local_normalize pol2)
    | K.Seq (pol1, pol2) ->
      seq_local_local (local_normalize pol1) (local_normalize pol2)
    | K.Star pol -> 
      star_local (local_normalize pol)
        
  let compile = local_normalize 

  let pat_to_netkat x =  
    if K.HeaderMap.is_empty x then
      K.True
    else
      let (h, v) = K.HeaderMap.min_binding x in
      let x' = K.HeaderMap.remove h x in
      let f h v pol = K.And (pol, K.Test (h, v)) in
      (K.HeaderMap.fold f x' (K.Test (h, v)))

  let pats_to_netkat xs = 
    if PatSet.is_empty xs then 
      K.False
    else
      let x = PatSet.choose xs in 
      let xs' = PatSet.remove x xs in 
      let f x pol = K.Or(pol, pat_to_netkat x) in 
      PatSet.fold f xs' (pat_to_netkat x)

  let act_to_netkat (pol : act) : K.policy =
    if K.HeaderMap.is_empty pol then
      K.Filter K.True
    else
      let (h, v) = K.HeaderMap.min_binding pol in
      let pol' = K.HeaderMap.remove h pol in
      let f h v pol' = K.Seq (pol', K.Mod (h, v)) in
      K.HeaderMap.fold f pol' (K.Mod  (h, v))

  let acts_to_netkat (pol : acts) : K.policy =
    if ActSet.is_empty pol then
      K.Filter K.False
    else
      let f seq pol' = K.Par (pol', act_to_netkat seq) in
      let seq = ActSet.min_elt pol in
      let pol' = ActSet.remove seq pol in
      ActSet.fold f pol' (act_to_netkat seq)

  let to_netkat (p:local) : K.policy = 
    let mk_par nc1 nc2 = 
      match nc1, nc2 with 
        | K.Filter K.False, _ -> nc2
        | _, K.Filter K.False -> nc1
        | _ -> K.Par(nc1,nc2) in       
    let mk_seq nc1 nc2 = 
      match nc1, nc2 with
        | K.Filter K.True, _ -> nc2
        | _, K.Filter K.True -> nc1
        | K.Filter K.False, _ -> nc1
        | _, K.Filter K.False -> nc2 
        | _ -> K.Seq(nc1,nc2) in 
    let mk_and pat1 pat2 = 
      match pat1,pat2 with 
        | K.False,_ -> pat1
        | _,K.False -> pat2
        | K.True,_ -> pat2
        | _,K.True -> pat1
        | _ -> K.And(pat1,pat2) in 
    let mk_not pat = 
      match pat with 
        | K.False -> K.True
        | K.True -> K.False
        | _ -> K.Neg(pat) in 
    let rec loop p = 
      if Local.is_empty p then 
        K.Filter K.False
      else
        let r,s = Local.min_binding p in
        let p' = Local.remove r p in 
        let (xs,x) = r in 
        let nc_pred = mk_and (mk_not (pats_to_netkat xs)) (pat_to_netkat x) in 
        let nc_pred_acts = mk_seq (K.Filter nc_pred) (acts_to_netkat s) in 
        mk_par nc_pred_acts (loop p') in 
    loop p

  let pred_to_pattern (sw : SDN_Types.fieldVal) (x:pat) : SDN_Types.pattern option =
    let f (h : K.header) (v : K.header_val) (pat : SDN_Types.pattern) =
      match h with
        | K.Switch -> pat (* already tested for this *)
        | K.Header h' -> SDN_Types.FieldMap.add h' v pat in
    if K.HeaderMap.mem K.Switch x &&
      K.HeaderMap.find K.Switch x <> sw then
      None
    else 
      Some (K.HeaderMap.fold f x SDN_Types.FieldMap.empty)
        
  let simpl_flow (p : SDN_Types.pattern) (a : SDN_Types.action) : SDN_Types.flow = {
    SDN_Types.pattern = p;
    SDN_Types.action = a;
    SDN_Types.cookie = 0L;
    SDN_Types.idle_timeout = SDN_Types.Permanent;
    SDN_Types.hard_timeout = SDN_Types.Permanent
  }

  let act_to_action (seq : act) : SDN_Types.action =
    if not (K.HeaderMap.mem (K.Header SDN_Types.InPort) seq) then
      SDN_Types.EmptyAction
    else
      let port = K.HeaderMap.find (K.Header SDN_Types.InPort) seq in
      let mods = K.HeaderMap.remove (K.Header SDN_Types.InPort) seq in
      let mk_mod (h : K.header) (v : K.header_val) (action : SDN_Types.action) =
        match h with
          | K.Switch -> raise (Invalid_argument "seq_to_action got switch update")
          | K.Header h' ->  SDN_Types.Seq (SDN_Types.SetField (h', v), action) in
      K.HeaderMap.fold mk_mod mods (SDN_Types.OutputPort port)

  let acts_to_action (sum : acts) : SDN_Types.action =
    let mk_par a1 a2 = 
      match a1,a2 with
        | SDN_Types.EmptyAction, _ -> a2
        | _, SDN_Types.EmptyAction -> a1
        | _ -> SDN_Types.Par(a1,a2) in 
    let f (seq : act) (action : SDN_Types.action) =
      mk_par action (act_to_action seq) in 
    ActSet.fold f sum SDN_Types.EmptyAction

(* Prunes out rules that apply to other switches. *)
  let local_to_table (sw:SDN_Types.fieldVal) (p:local) : SDN_Types.flowTable =
    Printf.printf "---- LOCAL ----\n%s\n%!" (to_string p);
    let add_flow x s l = 
      match pred_to_pattern sw x with
        | None -> l
        | Some pat -> simpl_flow pat (acts_to_action s) :: l in 
    let rec loop (p:local) acc cover = 
      if Local.is_empty p then 
        acc 
      else
        let r,s = Local.min_binding p in 
        let (xs,x) = r in 
        let p' = Local.remove r p in 
        let ys = PatSet.diff xs cover in 
        let acc' = PatSet.fold (fun x acc -> add_flow x ActSet.empty acc) ys acc in 
        let acc'' = add_flow x s acc' in 
        let cover' = PatSet.add x (PatSet.union xs cover) in 
        loop p' acc'' cover' in 
    List.rev (loop p [] PatSet.empty)
end