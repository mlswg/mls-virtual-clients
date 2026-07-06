---
title: MLS Virtual Clients
abbrev: MVC
docname: draft-ietf-mls-virtual-clients-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: J. Alwen
    name: Joël Alwen
    organization: "AWS"
    email: alwenjo@amazon.com
 -  ins: K. Kohbrok
    name: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad.kohbrok@datashrine.de
 -  ins: B. McMillion
    fullname: Brendan McMillion
    email: brendanmcmillion@gmail.com
 -  ins: "M. Mularczyk"
    name: "Marta Mularczyk"
    organization: "AWS"
    email: mulmarta@amazon.ch
 -  ins: R. Robert
    name: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

normative:
  NIST:
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
    title: "Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption"
    author:
      - name: Morris Dworkin

...

--- abstract

This document describes a method that allows multiple MLS clients to emulate a
virtual MLS client. A virtual client allows multiple emulator clients to jointly
participate in an MLS group under a single leaf. Depending on the design of the
application, virtual clients can help hide metadata and improve performance.

--- middle

# Introduction

The MLS protocol facilitates communication between clients, where in an MLS
group, each client is represented by the leaf to which it holds the private key
material. In this document, we propose the notion of a virtual client that is
jointly emulated by a group of emulator clients, where each emulator client
holds the key material necessary to act as the virtual client.

The use of a virtual client allows multiple distinct clients to be represented
by a single leaf in an MLS group. This pattern of shared group membership
provides a new way for applications to structure groups, can improve performance
and help hide group metadata. The effect of the use of virtual clients depends
largely on how it is applied (see {{applications}}).

We discuss technical challenges and propose a concrete scheme that allows a
group of clients to emulate a virtual client that can participate in one or more
MLS groups.

# Terminology

- Virtual Client: A client for which the secret key material is held by one or
  more emulator clients, each of which can act on behalf of the virtual client.
- Emulator Client: A client that collaborates with other emulator clients in
  emulating a virtual client.
- Emulation group: Group used by emulator clients to coordinate emulation of a
  virtual client.
- Higher-level group: A group that is not an emulation group and that may
  contain one or more virtual clients.
- Simple multi-client: A simple alternative to the concept of virtual clients,
  where entities that are represented by more than one client (e.g. a user with
  multiple devices) are implemented by including all of the entities' clients in
  all groups the entity is participating in.

TODO: Terminology is up for debate. We’ve sometimes called this “user trees”,
but since there are other use cases, we should choose a more neutral name. For
now, it’s virtual client emulation.

# Requirements Language

{::boilerplate bcp14-tagged-bcp14}

# Applications

Virtual clients generally allow multiple emulator clients to share membership in
an MLS group, where the virtual client is represented as a single leaf. This is
in contrast to the simple multi-client scenario as defined above.

Depending on the application, the use of virtual clients can have different
effects. However, in all cases, virtual client emulation introduces a small
amount of overhead for the emulator clients and certain limitations when it
comes to emulation group management (see {{emulation-group-management}}).

## Virtual clients for performance

If a group of emulator clients emulate a virtual client in more than one group,
the overhead caused by the emulation process can be outweighed by two
performance benefits.

On the one hand, the use of virtual clients makes the higher-level groups (in
which the virtual client is a member) smaller. Instead of one leaf for each
emulator client, it only has a single leaf for the virtual client. As the
complexity of most MLS operations depends on the number of group members, this
increases performance for all members of that group.

At the same time, the virtual client emulation process (see
{{client-emulation}}) allows emulator clients to carry the benefit of a single
operation in the emulation group to all higher-level groups in which the
virtual client is a member.

### Smaller trees

As a general rule, groups where one or more sets of clients are replaced by
virtual clients have fewer members, which leads to cheaper MLS operations where
the cost depends on the group size, e.g., commits with a path, the download size
of the group state for new members, etc. This increase in performance can offset
performance penalties, for example, when using a PQ-secure cipher suite, or if
the application requires high update frequencies.

### Fewer blanks

Blanks are typically created in the process of client removals. With virtual
clients, the removal of an emulator client will not cause the leaf of the
virtual client (or indeed any node in the virtual client's direct path) to be
blanked, except if it is the last remaining emulator client. As a result,
fluctuation in emulator clients does not necessarily lead to blanks in the group
of the corresponding virtual clients, resulting in fewer overall blanks and
better performance for all group members.

### Emulation costs

From a performance standpoint, using virtual clients only makes sense if the
performance benefits from smaller trees and fewer blanks outweigh the
performance overhead incurred by emulating the virtual client in the first
place.

## Metadata hiding

Virtual clients can be used to hide the emulator clients from other members of
higher-level groups. For example, removing group members of the emulation group
will only be visible in the higher-level group as a regular group update.
Similarly, when an emulator client wants to send a message in a higher-level
group, recipients will see the virtual client as the sender and won't be able to
discern which emulator client sent the message, or indeed the fact that the
sender is a virtual client at all.

Hiding emulator clients behind their virtual client(s) can, for example, hide
the number of devices a human user has, or which device the user is sending
messages from.

As hiding of emulator clients by design obfuscates the membership in
higher-level groups, it also means that other higher-level group members can't
identify the actual senders and recipients of messages. From the point of view
of other group members, the "end" of the end-to-end encryption and
authentication provided by MLS ends with the virtual client. The relevance of
this fact largely depends on the security goals of the application and the
design of the authentication service.

If the virtual client is used to hide the emulator clients, the delivery service and
other higher-level group members also lose the ability to enforce policies to
evict stale clients. For example, an emulator client could become stale (i.e.
inactive), while another keeps sending updates. From the point of view of the
higher-level group, the virtual client would remain active.

# Emulation group management

Managing the emulation group is more elaborate than performing simple MLS
operations within it.

When adding a new emulator client, there are several pieces of cryptographic
state that need to be synchronized before the new emulator client can start
using the virtual client. The emulator client can either get this state from
another emulator client, or if all other emulator clients are offline, the
emulator client can use a series of external joins to onboard itself.

## Adding an emulator client

A joining emulator client is added to the emulation group by a provisioning
emulator client via the usual MLS Add + Welcome. The GroupInfo in that
Welcome carries the `virtual_clients` component ({{iana-considerations}}),
whose component data is a NewEmulatorClientState struct that provides the
state the joining emulator client needs to act as the virtual client going
forward.

The NewEmulatorClientState struct contains the complete secret state of the
virtual client. Emulator clients MUST include it only in GroupInfo objects that
are encrypted as part of a Welcome message for the emulation group. In
particular, a GroupInfo object published to enable external commits into the
emulation group MUST NOT contain a `virtual_clients` component.

How the joining emulator client subsequently becomes an active participant in
each higher-level group is application-defined. This document specifies two
variants that the provisioning emulator client MAY use on a per-group basis:

- **Variant A (provisioning state transfer).** The provisioning emulator client
  includes, for each higher-level group, the key-schedule outputs of the current
  epoch together with the HPKE private keys on the virtual client's direct path.
  The joining emulator obtains the RatchetTree and the GroupContext from an
  application-defined source.
- **Variant B (external commit).** The provisioning emulator client only
  identifies which higher-level groups the virtual client is in. The joining
  emulator client acquires each group's current GroupInfo (from the DS or some
  other application-defined source) and performs an external commit into the
  group, evicting the virtual client's prior membership with a "resync" Remove
  proposal as described in {{Section 12.4.3.2 of !RFC9420}}.

Applications MAY mix the two variants across groups, for example using
Variant A for groups where metadata hiding matters and Variant B elsewhere.

Regardless of the variant chosen, a new emulator client MUST NOT send
PrivateMessages in a higher-level group while the DerivationInfo of
the active virtual-client LeafNode identifies an emulation-group epoch in which
the new emulator client was not a member. The new emulator client has no leaf
index at that epoch and therefore cannot compute the `reuse_guard` as described
in {{reuse-guard}}. Before the new emulator client can send messages in such a
higher-level group, the virtual-client LeafNode MUST be rotated (e.g., by a
Commit with an update path or an Update proposal followed by a Commit) to a
more recent emulation-group epoch in which the new emulator client is a member.

Note that in higher-level groups where handshake messages are sent as
PrivateMessages, the new emulator client cannot send this rotating Commit
itself. In such groups, the rotation has to be performed by an existing
emulator client, unless the application permits handshake messages framed as
PublicMessages or external commits (Variant B), in which case the new emulator
client can rotate the LeafNode itself.

### Trade-offs

- **Observability.** Variant A produces an ordinary Commit that looks like
  any other key rotation to the rest of the higher-level group. Variant B
  appears as the virtual client leaving and re-joining, which is visible to
  every member and may undermine metadata-hiding goals.
- **Forward secrecy.** Variant A chains the new epoch from the previous epoch's
  `init_secret`. Variant B breaks the commit chain resulting in weaker forward
  secrecy at the point of onboarding.
- **Policy.** Some applications may restrict external commits by policy leaving
  Variant A as the only option.
- **State transfer cost.** Variant A requires O(log N) HPKE private keys and the
  current epoch's key-schedule state per higher-level group. Depending on group
  size and the group's ciphersuite, this may exceed the application's
  performance constraints. Variant B's overhead is constant per group.

### State transfer protocol

Applications MAY use the following structs to transfer group data to the newly
added emulator client.

~~~ tls
opaque HPKEPrivateKey<V>;

struct {
  uint8 prefix_length;
  opaque prefix<V>;
  opaque node_secret<V>;
} PPRFNode;

struct {
  PPRFNode nodes<V>;
} PPRFState;

enum {
  reserved(0),
  key_package(1),
  leaf_node(2),
  application(3),
  (255)
} VirtualClientOperationType;

struct {
  opaque epoch_id<V>;
  VirtualClientOperationType operation_type;
  uint32 leaf_index;
  uint32 generation;
  opaque operation_context<V>;
  opaque operation_secret<V>;
} RetainedOperationSecret;

struct {
  uint32 node_index;
  opaque node_secret<V>;
} SecretTreeNodeState;

enum {
  reserved(0),
  application(1),
  handshake(2),
  operation(3),
  (255)
} SecretTreeRatchetType;

struct {
  uint32 leaf_index;
  SecretTreeRatchetType ratchet_type;
  select (SecretTreeRatchetState.ratchet_type) {
    case application:
      struct{};
    case handshake:
      struct{};
    case operation:
      VirtualClientOperationType operation_type;
  };
  uint32 generation;
  opaque next_secret<V>;
} SecretTreeRatchetState;

struct {
  SecretTreeNodeState node_secrets<V>;
  SecretTreeRatchetState ratchet_states<V>;
} SecretTreeState;

struct {
  KeyPackageRef key_package_ref;
  opaque epoch_id<V>;
  uint32 leaf_index;
  uint32 generation;
  uint32 key_package_index;
} KeyPackageDerivationInfo;

struct {
  opaque epoch_id<V>;
  uint32 leaf_index;
  uint32 generation;
  uint32 key_package_index;
  opaque key_package_seed_secret<V>;
} RetainedKeyPackageMaterial;

struct {
  opaque epoch_id<V>;
  SecretTreeState operation_secret_tree;
  opaque epoch_encryption_key<V>;
  opaque generation_id_secret<V>;
  opaque reuse_guard_secret<V>;
} EmulationEpochState;

enum {
  reserved(0),
  state_transfer(1),
  external_commit(2),
  (255)
} HigherLevelGroupStateType;

struct {
  opaque group_id<V>;
  HigherLevelGroupStateType state_type;
  select (HigherLevelGroupState.state_type) {
    case state_transfer:
      opaque init_secret<V>;
      opaque sender_data_secret<V>;
      opaque exporter_secret<V>;
      opaque external_secret<V>;
      opaque confirmation_key<V>;
      opaque membership_key<V>;
      opaque resumption_psk<V>;
      opaque epoch_authenticator<V>;
      SecretTreeState secret_tree;
      PPRFState safe_exporter_tree;
      HPKEPrivateKey direct_path_private_keys<V>;
    case external_commit:
      struct{};
  };
} HigherLevelGroupState;

struct {
  opaque signing_key_material<V>;
  KeyPackageDerivationInfo active_key_packages<V>;
  RetainedKeyPackageMaterial retained_key_package_material<V>;
  RetainedOperationSecret retained_operation_secrets<V>;
  EmulationEpochState past_emulation_epochs<V>;
  HigherLevelGroupState higher_level_groups<V>;
} NewEmulatorClientState;
~~~

- `HPKEPrivateKey` contains the serialized HPKE KEM private key for the
  ciphersuite used by the higher-level group.
- `PPRFState` serializes a punctured binary-tree PRF as the set of retained
  subtree roots. The root of an unpunctured tree is represented by a
  `PPRFNode` with `prefix_length` 0 and a zero-length `prefix`. For other
  nodes, `prefix` contains the first `prefix_length` bits of the node's path,
  packed from most-significant bit to least-significant bit in each octet. Any
  unused low-order bits in the final octet MUST be zero. The entries in
  `nodes` MUST be prefix-free and sorted lexicographically by prefix.
- `RetainedOperationSecret` carries an `operation_secret` whose operation
  ratchet generation has been deleted, but whose derived key material is still
  live. Entries are identified by `(epoch_id, operation_type, leaf_index,
  generation, operation_context)`.
- `RetainedKeyPackageMaterial` carries a `key_package_seed_secret` derived from
  a batch `key_package` operation secret whose operation-ratchet generation has
  been deleted. Entries are identified by `(epoch_id, leaf_index, generation,
  key_package_index)`.
- `SecretTreeState` serializes the retained state of an RFC 9420 Secret Tree.
  Each `SecretTreeNodeState` contains an unexpanded tree node secret and its
  RFC 9420 tree node index. Each `SecretTreeRatchetState` contains the current
  state of a derived per-leaf hash ratchet; `next_secret` is the ratchet secret
  that will be used to derive the secret for `generation`. The serialized state
  MUST contain exactly the retained secrets needed to continue the Secret Tree
  deletion schedule from the sender's current state and MUST NOT contain
  secrets that have already been deleted. The `application` and `handshake`
  ratchet types are used for higher-level MLS Secret Trees. The `operation`
  ratchet type is used for virtual-client operation secrets and includes an
  `operation_type` field that identifies the per-leaf operation-type ratchet.
- `signing_key_material` is an application-defined blob that conveys whatever
  signing-key state the joining emulator client needs. For configurations
  where signing keys are derived from emulation-group secrets, it MAY be
  zero-length. See {{generating-virtual-client-secrets}}.
- `active_key_packages` lists every KeyPackage the virtual client has
  outstanding. Each entry carries the KeyPackageRef together with the
  identifiers needed to find the corresponding per-KeyPackage material. When a
  Welcome arrives encrypted to one of these KeyPackages, the joining emulator
  client identifies the entry by KeyPackageRef, then finds the
  `RetainedKeyPackageMaterial` matching `(epoch_id, leaf_index, generation,
  key_package_index)`.
- `retained_key_package_material` contains per-KeyPackage seed secrets whose
  derived key material is still live, for example because the corresponding
  KeyPackage is outstanding or because the current LeafNode of a higher-level
  group was created from that seed secret. This includes the seed secret of
  the creator LeafNode of a higher-level group created by the virtual client
  ({{creating-groups-with-the-virtual-client}}), for which no KeyPackage
  exists.
- `retained_operation_secrets` contains retained `operation_secret` values
  whose derived key material is still live. This includes operation secrets for
  the current LeafNode of each higher-level group and operation secrets for
  sent but uncommitted LeafNodes or UpdatePaths. It MUST NOT include a
  `key_package` operation secret after that secret has been used to derive a
  KeyPackageUpload batch; KeyPackage-derived material is represented by
  `retained_key_package_material`.
  `retained_operation_secrets` is needed for the `state_transfer` onboarding
  variant because the joining emulator client needs to reconstruct still-live
  virtual-client artifacts whose operation-type ratchet generations have already
  been deleted. The `external_commit` onboarding variant does not require these
  retained operation secrets or retained KeyPackage material if it replaces
  every still-live virtual-client artifact derived from an earlier
  emulation-group epoch, including outstanding KeyPackages and active LeafNodes
  in higher-level groups.
- `past_emulation_epochs` carries, for every emulation-group epoch still
  referenced by an active LeafNode, outstanding KeyPackage, or retained
  operation secret or retained KeyPackage material and not equal to the current
  epoch, the retained `operation_secret_tree` state, the
  `epoch_encryption_key`, the `generation_id_secret`, and the
  `reuse_guard_secret`. State for the current emulation-group epoch is not
  included here because the joining emulator client derives it from the
  emulation group's Welcome.
- `higher_level_groups` contains one entry per active higher-level group.
  Each entry carries the `group_id` and a `state_type` identifying which
  variant applies.

For `state_transfer` entries, the provisioning emulator client transfers the
current epoch's key-schedule outputs and the retained per-epoch state:

- `init_secret` chains the joining emulator client's subsequent Commit
  into the next epoch (`init_secret[n-1]` combines with the new
  `commit_secret` to produce `joiner_secret[n]`).
- `sender_data_secret` lets the joining emulator client decrypt sender
  data on incoming PrivateMessages.
- `exporter_secret` lets the joining emulator client produce
  application-level exports from this epoch.
- `external_secret` lets other parties perform further external
  commits from this epoch.
- `confirmation_key` lets the joining emulator client verify the
  `confirmation_tag` on any incoming Commit.
- `membership_key` lets the joining emulator client produce a valid
  `membership_tag` on its own Commit sent as PublicMessage.
- `resumption_psk` lets the joining emulator client participate as an
  origin for resumption PSKs in this epoch, if the application uses them.
- `epoch_authenticator` authenticates the current group state.
- `secret_tree` is the current state of the group's Secret Tree, from
  which the joining emulator client derives per-member handshake- and
  application-ratchet keys needed to decrypt in-flight PrivateMessages.
- `safe_exporter_tree` is the current punctured state of the Safe Exporter API's
  Exporter Tree if the higher-level group uses that API. If the group does not
  use the Safe Exporter API, `nodes` is zero-length. When used for a Safe
  Exporter Tree, `PPRFState` paths are 16-bit paths indexed by `ComponentID`.
- `direct_path_private_keys` is the list of HPKE private keys for each non-blank
  node in the virtual client's filtered direct path. The first entry is the
  private key for the parent of the virtual client's leaf, if that node is
  non-blank. Subsequent entries correspond to the next non-blank nodes on the
  direct path toward the root, in order. The virtual client's leaf private key
  itself is derivable from the retained operation secret or retained
  per-KeyPackage material identified by the DerivationInfo on the current
  LeafNode and is therefore not transferred explicitly.

For `external_commit` entries, no additional per-group fields are included. The
joining emulator client external-commits into the group — fetching the current
GroupInfo from the DS or another application-defined source — and includes a
Remove proposal for the virtual client's prior leaf to evict the old membership.

## Joining externally

Without another online emulator client to bootstrap from, a new emulator can
join the emulation group externally. A prerequisite for this external join is
that the new client has the ability to learn which groups the virtual client is
in and to externally join those groups.

If those prerequisites are met, the new client needs to follow these steps:

1. Obtain a fresh credential that other emulation clients will accept.
2. Perform an external join to the emulation group.
3. Replace the virtual client's active key material by performing the following
   steps. Before each step, generate, derive or otherwise obtain the necessary
   credential and private signature key material. Ensure that other emulation
   clients can obtain the private key material. Details on credential and
   signature key generation and distribution are left to the application. The
   application MAY derive signature key material based on the new emulation
   group epoch as described in {{generating-virtual-client-secrets}}.

   1. Replace all active KeyPackages with new KeyPackages, generated from the
      new emulation group epoch.
   2. Perform an external join to all of the groups that the virtual client is a
      member of, using LeafNodes generated from the new emulation group epoch
      (see {{generating-virtual-client-secrets}}). Welcome messages which were
      unprocessed by the offline devices are discarded, and these groups are
      joined externally instead (potentially being queued for user approval
      first).

## Removing emulator clients

Since all emulator clients hold all key material of the virtual client, removing
the emulator client entails its removal from the emulation group, as well as
rotating or revoking any other virtual-client specific key material.

To effectively remove an emulator client, the emulator client committing the
proposal that removes the target client MUST take the following steps in order:

1. Effect the deletion of outstanding KeyPackages of the virtual client from the
   DS. The set of outstanding KeyPackages can be determined from the
   `KeyPackageUpload` messages previously sent to the emulation group (see
   {{creating-and-uploading-keypackages}}).
2. Commit a Remove proposal for the emulation client to be removed in the
   emulation group, advancing it to a new epoch from which new virtual client
   secrets will be derived (see {{generating-virtual-client-secrets}}).

Next, the application MUST provide new credentials and authentication key
material for the virtual client that can be used to replace existing credentials
and authentication key material in the next steps. The application MAY use the
`signature_key_secret` derived from any of the `operation_secret`s during the
next steps to derive group-specific key material. The application SHOULD take
steps to revoke any valid long lived credentials associated with the virtual
client that the removed emulator client had access to.

Using the new emulation-group epoch, any combination of remaining emulator
clients MUST do the following steps (in any order):

- Effect an update of the key material in every higher-level group in which the
  virtual client is a member, using the new credential and authentication key
  material provided by the application. This MAY be done by creating a commit
  with an update path or sending an update proposal.
- Upload a fresh set of KeyPackages derived from the new emulation-group epoch
  to replace those deleted in step 1.

A corollary of this removal procedure is that in most scenarios another emulator
client is required to be online and perform the necessary updates. The DS must
also support deletion of previously uploaded KeyPackages. This is in contrast to
the simple multi-client setup, where an external sender can effectively remove
individual clients and there are no additional functional requirements for the
DS.

# Client emulation

To ensure that all emulator clients can act through the virtual client, they
have to coordinate some of its actions.

Each emulation group MUST emulate exactly one virtual client. An emulation
group MAY emulate that virtual client in multiple higher-level groups, but the
virtual client MUST NOT be represented by more than one leaf in any given
higher-level group.

## Delivery Service

Client emulation requires that any message sent by an emulator client on behalf
of a virtual client be delivered not just to the rest of the higher-level group
to which the message is sent, but also to all other clients in the emulation
group.

## Generating Virtual Client Secrets

Generally, secrets for virtual client operations are derived from the emulation
group. To that end, emulator clients derive an `emulator_epoch_secret` with
every new epoch of that group using the Safe Exporter API defined in
{{Section 4.4 of !I-D.ietf-mls-extensions}}, where
`virtual_clients_component_id` is the component ID registered for the
`virtual_clients` component in {{iana-considerations}}.

~~~
emulator_epoch_secret = SafeExportSecret(virtual_clients_component_id)
~~~

The `emulator_epoch_secret` is in turn used to derive five further secrets, after
which it is deleted.

~~~
epoch_id =
  DeriveSecret(emulator_epoch_secret, "Epoch ID")
epoch_base_secret =
  DeriveSecret(emulator_epoch_secret, "Base Secret")
epoch_encryption_key =
  DeriveSecret(emulator_epoch_secret, "Encryption Key")
generation_id_secret =
  DeriveSecret(emulator_epoch_secret, "Generation ID Secret")
reuse_guard_secret =
  DeriveSecret(emulator_epoch_secret, "Reuse Guard")
~~~

The `epoch_base_secret` keys a Virtual Client Operation Secret Tree, a tree of
secrets with the same structure as the Secret Tree defined in Section 9 of
{{!RFC9420}}, with the following differences:

- Like the Secret Tree, the Virtual Client Operation Secret Tree has the same
  set of nodes and edges as the emulation group's ratchet tree at the
  corresponding epoch. The `node_index` fields of the serialized
  `SecretTreeState` are interpreted relative to this tree.
- The root of the tree is the `epoch_base_secret` rather than a secret derived
  from the `encryption_secret` of an MLS group epoch.
- Each leaf has one `operation` ratchet for each
  `VirtualClientOperationType`.

Emulator clients use the same ratchet advancement, skipping, and deletion
schedule for each operation ratchet as RFC 9420 uses for sender ratchets. An
emulator client that learns of an operation with generation `n` of a ratchet
whose current state is at generation `m < n` derives and retains the operation
secrets for the skipped generations `m, ..., n-1` in the same way RFC 9420
handles out-of-order PrivateMessages. Implementations SHOULD bound the number
of skipped generations they retain and the time for which they retain them.
The serialized state of the Virtual Client Operation Secret Tree is
represented by `SecretTreeState` with `SecretTreeRatchetState.ratchet_type`
set to `operation` and `SecretTreeRatchetState.operation_type` set to the
corresponding `VirtualClientOperationType`.

When a leaf secret in the Virtual Client Operation Secret Tree is expanded, the
initial operation ratchet secret for each non-reserved
`VirtualClientOperationType` defined in this document is derived as follows:

~~~
operation_ratchet_secret[operation_type][0] =
  ExpandWithLabel(leaf_secret, "vc operation init",
                  operation_type, Kdf.Nh)
~~~

In this derivation, `operation_type` is the TLS-encoded
`VirtualClientOperationType` value.

The `leaf_secret` MUST be deleted immediately after the initial operation
ratchet secrets for all operation types have been derived. As a consequence,
operation types defined by future documents cannot be added to already
expanded leaves; they are only usable from emulation-group epochs onward in
which all emulator clients derive them at expansion time.

Emulator clients MUST retain the `operation_secret_tree`, the `epoch_id`, the
`epoch_encryption_key`, the `generation_id_secret`, the `reuse_guard_secret`,
and the number of leaf nodes the emulation group's ratchet tree had at the
corresponding epoch (including blank leaves, see {{reuse-guard}}) until no key
material associated with that epoch is actively used anymore and no generation
IDs or reuse guards need to be computed for that epoch. For each retained
epoch in which an emulator client was a member, it MUST also retain its own
leaf index at that epoch. The `operation_secret_tree`, `epoch_id`, and
`epoch_encryption_key` are used for deriving and processing virtual-client key
material, including DerivationInfos and state transferred to new clients
({{adding-an-emulator-client}}); the `generation_id_secret` is used for
computing generation IDs ({{coordinating-ratchet-generations-with-the-ds}});
and the `reuse_guard_secret`, leaf count, and leaf index are used for
computing the `reuse_guard` ({{reuse-guard}}).

When deriving a secret for a virtual client, e.g. for use in a KeyPackage
upload or LeafNode update, the deriving client chooses a
`VirtualClientOperationType` and uses the next unused generation of its own
operation ratchet for that operation type. The `operation_type` is
`key_package` when deriving per-KeyPackage seed secrets, either for a
KeyPackageUpload batch or for the creator LeafNode of a newly created
higher-level group ({{creating-groups-with-the-virtual-client}}). A single
`key_package` operation generation derives the batch operation secret for all
KeyPackages in that upload, and individual KeyPackages are domain-separated
with `key_package_index` as described in
{{creating-and-uploading-keypackages}}. The batch is closed by the upload:
after a KeyPackageUpload has been sent, the same operation generation MUST NOT
be used to derive additional KeyPackages. The `operation_type` is `leaf_node`
when creating a LeafNode for an Update proposal, a Commit with an update path,
or an external commit. Applications MAY use the operation type `application`
to derive application-specific key material.

Deriving an `operation_secret` consumes the corresponding operation-ratchet
generation, even if the virtual-client operation does not result in a
higher-level MLS message that is accepted into the higher-level group's
transcript. Once a generation has been consumed, an emulator client MUST NOT use
the same generation of the same operation-type ratchet for another virtual-client
operation. A retry of a failed operation is another virtual-client operation:
if, for example, a group creation or an external commit is rejected and
attempted again, the retry MUST consume a fresh generation. If the operation
fails, the emulator client MUST delete any retained secret material derived
from the failed operation after the client determines that the operation will
not be used.

The operation context is a value bound into the derivation of the
`operation_secret`. For `key_package` operations, `operation_context` is a
zero-length octet string. For `leaf_node` operations, `operation_context` is the
`group_id` of the higher-level group in which the LeafNode is used. For
`application` operations, `operation_context` is application-defined and MUST be
authenticated by the application together with the other derivation inputs.

~~~
struct {
  opaque epoch_id<V>;
  uint32 leaf_index;
  uint32 generation;
  VirtualClientOperationType operation_type;
  opaque operation_context<V>;
} OperationContext;

operation_generation_secret =
  DeriveSecret(operation_ratchet_secret, "VC Operation Secret")

next_operation_ratchet_secret =
  DeriveSecret(operation_ratchet_secret, "VC Operation Ratchet")

operation_secret =
  ExpandWithLabel(operation_generation_secret, "vc operation",
                  OperationContext, Kdf.Nh)
~~~

`operation_ratchet_secret` is the ratchet secret for `generation` in the
`operation_type` ratchet of `leaf_index`. After deriving `operation_secret` and
`next_operation_ratchet_secret`, the emulator client MUST delete
`operation_ratchet_secret` and `operation_generation_secret` and update the
ratchet state for the selected `operation_type` to
`next_operation_ratchet_secret` for `generation + 1`. The emulator client MUST
retain enough secret material to reproduce all active key material derived from
`operation_secret`. For `key_package` operations, the emulator client derives
the per-KeyPackage seed secrets for every KeyPackage in the batch and MUST
delete the batch `operation_secret` after all per-KeyPackage material needed
for the batch has been derived.

Retaining `operation_secret`s and per-KeyPackage seed secrets beyond their
immediate use is only necessary if the application intends to onboard new
emulator clients through provisioning state transfer (Variant A,
{{adding-an-emulator-client}}). If that is the case, the emulator client MUST
retain them as RetainedOperationSecrets and RetainedKeyPackageMaterial until
all key material derived from them is no longer active, and MUST delete them
after that point. Otherwise, the emulator client MUST delete them as soon as
it has derived the key material required for the operation. The derived key
material that remains in use (such as the `init_key` private key of an
outstanding KeyPackage) is retained independently of the secret it was
derived from.

Given an `epoch_id`, `operation_type`, `generation`, `operation_context`, and
the `leaf_index` of the emulator client performing the virtual client
operation, other emulator clients can derive the `operation_secret`, advance the
same operation-type ratchet, and use the `operation_secret` to perform the same
operation. For `key_package` operations, they also use `key_package_index` to
derive the per-KeyPackage seed secret from the batch `operation_secret`. If the
operation-type ratchet generation has already been deleted and the operation
was not a `key_package` operation, for example because the emulator client
joined after the operation took place, the emulator client uses the
corresponding RetainedOperationSecret transferred in NewEmulatorClientState.
For KeyPackage-derived material, the emulator client uses the corresponding
RetainedKeyPackageMaterial, identified either by DerivationInfo or by an
`active_key_packages` entry.

Depending on the operation, the acting emulator client will have to derive one
or more secrets from the `operation_secret`.

This document defines four types of MLS-related secrets derived from virtual
client operations.

- `signature_key_secret`: Used to derive the signature key in a virtual client's
  leaf
- `init_key_secret`: Used to derive the `init_key` HPKE key in a KeyPackage
- `encryption_key_secret`: Used to derive the `encryption_key` HPKE key in the
  LeafNode of a virtual client
- `path_generation_secret`: Used to generate `path_secret`s for the UpdatePath
  of a virtual client

For operations that do not use a per-KeyPackage seed secret, the MLS-related
secrets are derived directly from the `operation_secret`:

~~~
signature_key_secret =
  DeriveSecret(operation_secret, "Signature Key")

encryption_key_secret =
  DeriveSecret(operation_secret, "Encryption Key")

init_key_secret =
  DeriveSecret(operation_secret, "Init Key")

path_generation_secret =
  DeriveSecret(operation_secret, "Path Generation")
~~~

For `key_package` operations, the KeyPackageUpload derives one batch
`operation_secret`. For each KeyPackageInfo in the upload, the creating
emulator client derives a per-KeyPackage seed secret from that batch
`operation_secret` using the KeyPackage's `key_package_index` as KDF context:

~~~ tls
struct {
  uint32 key_package_index;
} KeyPackageSeedContext;
~~~

~~~
key_package_seed_secret =
  ExpandWithLabel(operation_secret, "key package seed",
                  KeyPackageSeedContext, Kdf.Nh)
~~~

The KeyPackage's `init_key_secret`, `signature_key_secret`, and
`encryption_key_secret` are derived from `key_package_seed_secret`, not
directly from the batch `operation_secret`:

~~~
signature_key_secret =
  DeriveSecret(key_package_seed_secret, "Signature Key")

encryption_key_secret =
  DeriveSecret(key_package_seed_secret, "Encryption Key")

init_key_secret =
  DeriveSecret(key_package_seed_secret, "Init Key")
~~~

The source of the virtual client's signature key is application-defined. An
application MAY use `signature_key_secret` to derive a fresh signing key per
operation, or MAY provide signing-key material through other means, for
example a per-group or global signing key issued by the Authentication
Service, or a signing key derived from an emulation-group epoch secret.
Whatever the choice, the `signing_key_material` field of
NewEmulatorClientState (see {{adding-an-emulator-client}}) carries the
state a new emulator client needs; its contents are application-defined.

## Creating LeafNodes and UpdatePaths

When creating a LeafNode, either for group creation, a Commit with an update
path, an Update proposal, an external commit, or a KeyPackage, the creating
emulator client MUST derive the necessary secrets from the current epoch of the
emulation group as described in {{generating-virtual-client-secrets}}.
For a LeafNode whose `leaf_node_source` is `key_package`, the creating emulator
client MUST use a per-KeyPackage seed secret, derived from a batch
`key_package` operation secret and the LeafNode's `key_package_index`. For the
LeafNode of a KeyPackage, this MUST be the same seed secret used to derive the
KeyPackage's `init_key_secret`. For the creator LeafNode of a newly created
higher-level group, the seed secret is derived from a dedicated `key_package`
operation as described in {{creating-groups-with-the-virtual-client}}. For a
LeafNode whose `leaf_node_source` is `update` or `commit`, the creating
emulator client MUST use a `leaf_node` operation secret.

Similarly, if an emulator client generates a Commit with an update path, it
MUST use `path_generation_secret` as the `path_secret` for the first
`parent_node` instead of generating it randomly.

To signal to other emulator clients which epoch to use to derive the necessary
secrets to recreate the key material, the emulator client includes a
DerivationInfo struct as the `virtual_clients` component data in the LeafNode.

~~~ tls
struct {
  opaque epoch_id<V>;
  opaque ciphertext<V>;
} DerivationInfo;

struct {
  opaque init_secret<V>;
} ExternalInitSecret;

struct {
  uint32 leaf_index;
  uint32 generation;
  select (LeafNode.leaf_node_source) {
    case key_package:
      uint32 key_package_index;
    case update:
      struct{};
    case commit:
      optional<ExternalInitSecret> external_init_secret;
  };
} DerivationInfoTBE;
~~~

For a LeafNode in an external Commit, `external_init_secret` MUST contain the
`init_secret` produced by external initialization as described in
{{Section 8.3 of !RFC9420}}. For a LeafNode in any other Commit, the
`external_init_secret` field MUST be absent.

The `ciphertext` is the serialized DerivationInfoTBE encrypted with the AEAD
scheme of the emulation group's ciphersuite, with the `epoch_id` as AAD. The
`LeafNode.leaf_node_source` selector is the `leaf_node_source` of the LeafNode
carrying the DerivationInfo. The AEAD key and nonce are derived from the
epoch's `epoch_encryption_key`, using
the serialized `encryption_key` field of the LeafNode carrying the component
as context:

~~~
derivation_info_key = ExpandWithLabel(epoch_encryption_key, "key",
                                      encryption_key, AEAD.Nk)
derivation_info_nonce = ExpandWithLabel(epoch_encryption_key, "nonce",
                                        encryption_key, AEAD.Nn)
~~~

Since every virtual-client operation produces a LeafNode with a fresh
`encryption_key`, each distinct DerivationInfoTBE is encrypted under a
distinct key-nonce pair. Re-encrypting the same DerivationInfoTBE for the same
LeafNode yields an identical ciphertext, which is benign. This only holds
because a consumed operation-ratchet generation is never reused: for external
Commit LeafNodes, the DerivationInfoTBE contains the `external_init_secret`,
which changes with every encapsulation. Deriving a LeafNode for a retried
external Commit from the same generation would therefore encrypt a different
DerivationInfoTBE under the same key and nonce and compromise the AEAD.
Instead, the retry MUST consume a fresh generation as described in
{{generating-virtual-client-secrets}}.

The operation type used to derive the LeafNode's `operation_secret` is
determined by the LeafNode's `leaf_node_source`
({{Section 7.2 of !RFC9420}}): `key_package` maps to `key_package`, while
`update` and `commit` map to `leaf_node`. The `operation_context` is
determined by the operation type as described in
{{generating-virtual-client-secrets}}: zero-length for `key_package`
operations, and the `group_id` of the higher-level group in which the LeafNode
is used for `leaf_node` operations. The `leaf_index` and `generation` fields
MUST be the values used with that operation type and operation context to
derive the LeafNode's `operation_secret`. For KeyPackage LeafNodes,
`generation` identifies the batch `key_package` operation generation and
`key_package_index` identifies the individual KeyPackage within that batch. For
`leaf_node` operations, the DerivationInfoTBE contains no `key_package_index`.
For external Commit LeafNodes, the DerivationInfoTBE additionally carries the
external init secret needed to process the Commit.

When other emulator clients receive a LeafNode for the virtual client, they use
the `epoch_id` to determine the epoch of the emulation group from which to
derive the secrets necessary to re-create the key material of the LeafNode and
potential UpdatePath. They decrypt the DerivationInfo and use the operation
type determined from the LeafNode's `leaf_node_source`, together with the
`leaf_index` and `generation` fields, as inputs to the operation secret
derivation described in {{generating-virtual-client-secrets}}. For a KeyPackage
LeafNode, they then use `key_package_index` to derive the per-KeyPackage seed
secret from the batch `key_package` operation secret and use that seed to
re-create the LeafNode key material.

When processing an external Commit sent by the virtual client, an emulator
client uses the `external_init_secret` from the DerivationInfoTBE as the
external init secret for the new epoch. If `external_init_secret` is absent,
the emulator client MUST reject the Commit.

The `external_init_secret` is carried in the DerivationInfo because the other
emulator clients cannot always derive it themselves. If the external Commit
resynchronizes the virtual client's membership in a group it is already a
member of, the other emulator clients hold the previous epoch's
`external_secret` and could recover the init secret from the `kem_output` in
the ExternalInit proposal ({{Section 8.3 of !RFC9420}}). If the virtual client
externally joins a group it was not previously a member of, however, they hold
no prior epoch state for that group and cannot. Carrying the init secret in
the DerivationInfo covers both cases uniformly.

The `DerivationInfo` on the active virtual-client LeafNode binds that
virtual client's membership in the higher-level group to the emulation-group
epoch identified by `epoch_id`. Protocol steps that require per-epoch
emulation-group state for a higher-level group, such as computing the
`reuse_guard` ({{reuse-guard}}) or a generation ID
({{coordinating-ratchet-generations-with-the-ds}}), MUST use the
emulation-group epoch identified by the active virtual-client LeafNode.

## Creating groups with the virtual client

When an emulator client creates a higher-level group with the virtual client as
the creator, it MUST create the initial LeafNode as described in
{{creating-leafnodes-and-updatepaths}}. {{!RFC9420}} does not prescribe a
`leaf_node_source` for the creator's LeafNode. The creator LeafNode of a
virtual client MUST have `leaf_node_source` `key_package`. Since no KeyPackage
is published for this LeafNode, the creating emulator client derives its key
material from a dedicated `key_package` operation: it consumes a fresh
`key_package` operation-ratchet generation and derives a single per-KeyPackage
seed secret with `key_package_index` 0. No KeyPackageUpload is sent for this
operation. The batch consists of only this derivation and is closed
immediately, and the batch `operation_secret` is deleted after the seed secret
has been derived.

Like any other LeafNode with `leaf_node_source` `key_package`, the creator
LeafNode carries a `lifetime` ({{Section 7.2 of !RFC9420}}), and members
validating the ratchet tree, including members joining later, may reject a
leaf whose lifetime has expired. The creating emulator client SHOULD choose
the lifetime according to the application's LeafNode validity policy, and the
virtual client's leaf SHOULD be updated before the lifetime expires.

Instead of choosing the initial epoch secret of the new group randomly as
described in {{Section 11 of !RFC9420}}, the creating emulator client MUST
derive it from the creator LeafNode's per-KeyPackage seed secret:

~~~
epoch_secret = DeriveSecret(key_package_seed_secret, "Group Creation")
~~~

DeriveSecret is computed with the higher-level group's ciphersuite, so that
`epoch_secret` has the size KDF.Nh required by that group's key schedule. This
makes the initial epoch state of the higher-level group derivable by every
emulator client from the DerivationInfo on the creator LeafNode alone, and it
makes retried group creation attempts, each of which consumes a fresh
generation (see {{generating-virtual-client-secrets}}), independent of one
another.

The application MUST fan out the initial group creation material to all current
emulator clients before delivering any other content from that higher-level
group to those emulator clients. The initial group creation material consists
of the GroupInfo for the newly created group, the creator LeafNode or a
ratchet_tree extension that contains it, and any application-defined context
needed to associate the material with the higher-level group. An emulator
client MUST process the initial group creation material before processing any
other content from that higher-level group. This requirement parallels the one
for external join material in
{{externally-joining-groups-with-the-virtual-client}}.

When processing initial group creation material, an emulator client verifies
the GroupInfo as described in {{Section 12.4.3.1 of !RFC9420}} and the ratchet
tree as described in {{Section 12.4.3.3 of !RFC9420}}, decrypts the
DerivationInfo in the creator LeafNode, reconstructs the LeafNode's key
material as described in {{creating-leafnodes-and-updatepaths}}, re-derives
`epoch_secret` from the same per-KeyPackage seed secret, and uses it to
initialize the higher-level group's epoch 0 state. If the GroupInfo cannot be
verified using the resulting epoch state, the emulator client MUST reject the
initial group creation material.

## Virtual client actions

Emulator clients sometimes need to communicate directly to operate the virtual
client. The acting emulator client can attach such information to a Commit to
the emulation group using the SafeAAD mechanism described in
{{Section 4.9 of !I-D.ietf-mls-extensions}}. The SafeAAD component data of the
`virtual_clients` component is a VirtualClientAction struct.

Sending an action as part of a Commit serves two purposes: First, the
agreement on message ordering facilitated by the DS prevents concurrent
conflicting actions by two or more emulator clients. Second, the action is
authenticated as part of the Commit.

The `key_package_upload` action is one way applications MAY use to communicate
a KeyPackageUpload message ({{creating-and-uploading-keypackages}}) to the
other emulator clients.

~~~ tls
enum {
  reserved(0),
  key_package_upload(1),
  (255)
} ActionType;

struct {
  ActionType action_type;
  select (VirtualClientAction.action_type) {
    case key_package_upload:
      KeyPackageUpload key_package_upload;
  };
} VirtualClientAction;
~~~

### Creating and uploading KeyPackages

When creating KeyPackages to upload, the creating emulator client derives one
`key_package` operation secret using `(epoch_id, leaf_index, generation,
operation_type = key_package, operation_context = zero-length)`, as described
in {{generating-virtual-client-secrets}}. The `generation` is the single
`key_package` operation-ratchet generation used for the whole upload batch. For
each KeyPackage, the creating emulator client chooses a `key_package_index` and
derives the `init_key_secret`, `signature_key_secret`, and
`encryption_key_secret` from the per-KeyPackage seed secret derived using that
index. The `key_package_index` values in a KeyPackageUpload MUST be unique.
Senders SHOULD use consecutive values starting at zero.

The KeyPackage's LeafNode MUST contain a DerivationInfo as described in
{{creating-leafnodes-and-updatepaths}} whose encrypted DerivationInfoTBE
contains the same `leaf_index`, `generation`, and `key_package_index` values
used for the KeyPackage. The `generation` value MUST be the generation reported
in the corresponding KeyPackageUpload message, and the `key_package_index`
field, which is present for KeyPackage LeafNodes, MUST be the value reported
for this KeyPackageRef in that upload.

The KeyPackageUpload closes the batch. After sending the KeyPackageUpload, the
creating emulator client MUST NOT use the same operation generation to derive
additional KeyPackages. After deriving all per-KeyPackage material needed for
the upload, the creating emulator client MUST delete the batch
`operation_secret`.

To make other emulator clients aware of the new KeyPackages and allow them to
process any corresponding Welcome messages, the creating client MUST send them
a KeyPackageUpload message covering all new KeyPackages before making the
KeyPackages available to other parties.

~~~ tls
struct {
  KeyPackageRef key_package_ref;
  uint32 key_package_index;
} KeyPackageInfo;

struct {
  opaque epoch_id<V>;
  uint32 leaf_index;
  uint32 generation;
  KeyPackageInfo key_package_info<V>;
} KeyPackageUpload;
~~~

- `key_package_ref`: The hash reference of the generated KeyPackage computed as
  described in {{Section 5.2 of !RFC9420}}.
- `key_package_index`: A sender-chosen counter used as KDF context to
  domain-separate this KeyPackage from the other KeyPackages in the same
  KeyPackageUpload. It MUST be unique within the KeyPackageUpload.
- `epoch_id`: The epoch ID of the emulation group epoch used to derive the
  batch `key_package` operation secret
- `leaf_index`: The leaf index of the emulator client in the emulation group
  that created the KeyPackages
- `generation`: The single `key_package` operation-ratchet generation used to
  derive the batch operation secret for this KeyPackageUpload
- `key_package_info`: The information required to re-derive the
  `init_key_secret` for each individual KeyPackage

Any emulator client that receives a KeyPackageUpload message MUST verify that
the `key_package_index` values are unique within the upload and MUST reject the
upload otherwise. The recipient uses `epoch_id`, `leaf_index`, `generation`,
`operation_type` `key_package`, and the zero-length `operation_context` to
derive the batch `operation_secret`. For each KeyPackageInfo, the recipient
uses `key_package_index` to derive the per-KeyPackage seed secret, then derives
the KeyPackage's `init_key` and LeafNode key material from that seed. If the
recipient receives a Welcome, it can then check which `init_key` to use based
on the KeyPackageRef.

To preserve outstanding KeyPackage semantics, recipients MUST process the
KeyPackageUpload at receipt time and retain per-KeyPackage material sufficient
to process any Welcome for each listed KeyPackageRef. After deriving the
per-KeyPackage material needed for the upload, recipients MUST delete the batch
`operation_secret`.

How the creating client sends the message to the other emulator clients is up
to the application, as long as every current emulator client receives it before
the KeyPackages are made available and emulator clients added later receive
equivalent state via `active_key_packages` in NewEmulatorClientState. One way
to send the message is the
`key_package_upload` action described in {{virtual-client-actions}}.

### Externally joining groups with the virtual client

An emulator client that uses an external commit to join a group with the virtual
client relies on the higher-level group's Commit sequencing rules to determine
whether that external commit is accepted. When creating the Commit to join the
group externally, it MUST generate the LeafNode and path as described in
{{creating-leafnodes-and-updatepaths}}.

An external Commit sent on behalf of the virtual client reaches the other
emulator clients like any other virtual-client message (see
{{delivery-service}}). If the virtual client was already a member of the
group, the other emulator clients hold the group's state and process the
external Commit like any other handshake message. If the virtual client
externally joins a group it was not previously a member of, however, the
other emulator clients hold no state for that group and cannot process the
Commit by itself.

For such groups, the application MUST make the external join material
available to all current emulator clients before delivering any other content
from that higher-level group to them. The external join material consists of
the GroupInfo the joining emulator client used to create the external Commit,
the ratchet tree of the corresponding epoch (unless it is carried in the
GroupInfo's `ratchet_tree` extension), and any application-defined context
needed to associate the material with the higher-level group. An emulator
client MUST process the external join material together with the external
Commit before processing any other content from that higher-level group.

When processing external join material, an emulator client verifies the
GroupInfo as described in {{Section 12.4.3.2 of !RFC9420}} and the ratchet
tree as described in {{Section 12.4.3.3 of !RFC9420}} before applying the
external Commit.

## Sending PrivateMessages

Given that MLS generates the encryption keys and nonces for PrivateMessages
sequentially, but multiple emulator clients may send messages through the
virtual client simultaneously, this can create a situation where encryption keys
and nonces are reused inappropriately. Critically, if two emulator clients
encrypt a message with both the same key and nonce simultaneously, this could
compromise the message's confidentiality and integrity. Emulator clients MUST
prevent this by computing the `reuse_guard`, as described below instead of
sampling it randomly.

### Small-Space PRP

A small-space pseudorandom permutation (PRP) is a cryptographic algorithm that
works similar to a block cipher, while also being able to adhere to format
constraints. In particular, it is able to perform a pseudorandom permutation
over an arbitrary input and output space.

This document uses the FF1 mode from {{NIST}} instantiated with AES-128 as the
underlying block cipher, with radix 2, numeral strings of length 32, and an
empty tweak. A 32-bit unsigned integer is mapped to a numeral string by listing
its bits from most significant to least significant; the output numeral string
is mapped back to a 32-bit unsigned integer in the same way.

~~~
output = SmallSpacePRP.Encrypt(key, input)
input = SmallSpacePRP.Decrypt(key, output)
~~~

`key` is a 16-byte AES-128 key; `input` and `output` are 32-bit unsigned
integers. Where a 4-byte value such as the `reuse_guard` is required, the
integer is encoded in network byte order (big-endian).

### Reuse Guard

MLS clients typically generate the bytes for the `reuse_guard` randomly. When
sending a message with a virtual client, however, emulator clients choose a
random value `x` such that `x` modulo `N_e` is equal to `leaf_index_e`, where:

- `e` is the emulation-group epoch that produced the active virtual-client
  LeafNode in the higher-level group, identified by the `epoch_id` field of
  that LeafNode's `DerivationInfo` (see
  {{creating-leafnodes-and-updatepaths}}).
- `N_e` is the number of leaf nodes in the emulation group's ratchet tree at
  epoch `e`, including blank leaves (see {{Section 7.7 of !RFC9420}}). Since
  the ratchet tree is always full, `N_e` is a power of two, every member's
  leaf index is strictly less than `N_e`, and no two emulator clients share
  the same residue modulo `N_e`.
- `leaf_index_e` is the encrypting emulator client's leaf index in the
  emulation group at epoch `e`.

They then calculate:

~~~
prp_key = ExpandWithLabel(reuse_guard_secret, "reuse guard",
                          key_schedule_nonce, 16)
reuse_guard = SmallSpacePRP.Encrypt(prp_key, x)
~~~

ExpandWithLabel is computed with the emulation group's ciphersuite's algorithms.
`reuse_guard_secret` is derived as described in
{{generating-virtual-client-secrets}} for emulation-group epoch `e`, identified
by the virtual client's currently active LeafNode in the higher-level group.
`key_schedule_nonce` is the nonce provided by the key schedule for encrypting
this message.

`prp_key` is computed in a way that it is unique to the key-nonce pair and
computable by all emulator clients (but nobody else). `reuse_guard` is computed
in a way that it appears random to outside observers (in particular, it does not
leak which emulator client sent the message), but two emulator clients will
never generate the same value.

Recipient emulator clients can use the `reuse_guard` to recover the sender's
leaf index in the emulation group. Since they share `reuse_guard_secret` and
have access to `key_schedule_nonce` for the message, they can re-derive
`prp_key` and invert the PRP to obtain `x = SmallSpacePRP.Decrypt(prp_key,
reuse_guard)`. The encrypting emulator client's leaf index in the emulation
group at epoch `e` is then `leaf_index_e = x mod N_e`, where `e` and `N_e` are
determined as described above. This allows recipients to attribute application
messages to specific emulator clients without revealing the sender to outside
observers.

### Coordinating ratchet generations with the DS

The method discussed above for computing `reuse_guard` prevents emulator clients
from ever reusing the same key-nonce pair, as this would compromise the message.
However, it does not prevent different emulator clients from attempting to
encrypt messages with the same key but different nonces. While this doesn't
create any security issues, it is a functionality issue due to the MLS deletion
schedule. Other higher level group members (or indeed emulator clients) will
delete the encryption key after using it to decrypt the first message they
receive and will be unable to decrypt subsequent messages.

The best solution depends on whether the Delivery Service is strongly or
eventually consistent {{!RFC9750}}. Emulator clients communicating with a
strongly-consistent DS SHOULD prevent this issue by coordinating the use of
individual ratchet generations for encryption through the DS. Emulator clients
MAY send a generation ID to the DS whenever they fan out a private message. The
generation ID is derived as follows.

~~~ tls
enum {
  reserved(0),
  application(1),
  handshake(2),
  (255)
} RatchetType;

struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 generation;
  RatchetType ratchet_type;
} PrivateMessageContext;

generation_id = ExpandWithLabel(generation_id_secret, "generation id",
                      PrivateMessageContext, Kdf.Nh)
~~~

- `group_id` is the `group_id` of the higher-level group in which the
  PrivateMessage is sent
- `epoch` is the epoch of that higher-level group at which the
  PrivateMessage is sent
- `generation` is the generation of the ratchet used for encryption
- `ratchet_type` is the type of ratchet used to encrypt the PrivateMessage
- ExpandWithLabel as defined in {{!RFC9420}}
- `generation_id_secret` is derived as specified in
  {{generating-virtual-client-secrets}} for the emulation-group epoch identified
  by the active virtual-client LeafNode in the higher-level group
- `Kdf.Nh` is from the emulation group's ciphersuite

Attaching the generation ID to the PrivateMessage allows the DS to detect
collisions between generations per higher-level group, per higher-level group
epoch and per ratchet type.

Alternatively, devices communicating with an eventually-consistent DS may need
to simply retain messages and encryption keys for a short period of time after
sending, in case it becomes necessary to decrypt another device's message and
re-encrypt and re-send their original message with another encryption key.

# Security Considerations

## Trust between emulator clients

All emulator clients hold the complete secret state of the virtual client.
Compromise of a single emulator client is therefore equivalent to compromise of
the virtual client itself: the attacker learns the current epoch secrets of the
emulation group and of every higher-level group the virtual client is a member
of, and can impersonate the virtual client in all of them. Emulator clients
have to trust each other fully; the emulation group does not provide any
isolation between them.

## Forward secrecy

Forward secrecy for messages in higher-level groups depends on every emulator
client deleting consumed key material according to the deletion schedule of
{{Section 9.2 of !RFC9420}}. Since every emulator client processes every
message sent to a higher-level group, the effective forward secrecy of such a
group is bounded by the emulator client that is slowest to advance its ratchets
and delete its keys. The same applies to the retained state defined in this
document: RetainedOperationSecrets, RetainedKeyPackageMaterial, and past
emulation-epoch state ({{adding-an-emulator-client}}) extend the window during
which a compromise reveals previously transmitted data, and emulator clients
SHOULD delete them as soon as they are no longer needed. Applications that do
not onboard emulator clients through state transfer need not retain
RetainedOperationSecrets or RetainedKeyPackageMaterial at all (see
{{generating-virtual-client-secrets}}) and can instead retain only the derived
key material still in use, reducing this window.

Some of this state is reachable through the virtual client's LeafNodes. The
DerivationInfo of an external Commit LeafNode embeds the `init_secret` of the
epoch created by that Commit, encrypted under the emulation-group epoch's
`epoch_encryption_key`. The LeafNode persists in the higher-level group's
ratchet tree until the virtual client's leaf is next updated, and emulator
clients retain the `epoch_encryption_key` for as long as the LeafNode is
active. Similarly, the initial epoch secret of a higher-level group created by
the virtual client remains derivable from the retained per-KeyPackage seed
secret of the creator LeafNode
({{creating-groups-with-the-virtual-client}}). Updating the virtual client's
LeafNode soon after an external commit or a group creation allows emulator
clients to delete this state and limits the exposure.

## Post-compromise security

Some of the performance benefits of this scheme depend on the fact that one can
update once in the emulation group and "re-use" the new randomness for updates
in multiple higher-level groups. At that point, clients only really recover when
they update the emulation group, i.e. re-using somewhat old randomness of the
emulation group won't provide real PCS in higher-level groups.

## Removing emulator clients

The removal procedure in {{removing-emulator-clients}} is not atomic. Between
the Commit that removes an emulator client from the emulation group and the
completion of the key rotations in all higher-level groups, the removed client
still holds valid key material for those groups and can read traffic in them
and impersonate the virtual client. Applications SHOULD minimize this window
and SHOULD revoke any long-lived credentials the removed client had access to,
since a removed client that retains a valid virtual-client signing key and
credential can otherwise re-join a higher-level group via an external commit.
The procedure also depends on the DS actually deleting outstanding KeyPackages;
a KeyPackage that escapes deletion allows the removed client to process
Welcome messages addressed to the virtual client.

## Handling of NewEmulatorClientState

The NewEmulatorClientState struct contains the complete secret state of the
virtual client and MUST only appear in GroupInfo objects encrypted within
Welcome messages, as specified in {{adding-an-emulator-client}}. Publishing a
GroupInfo containing the `virtual_clients` component, for example to enable
external commits, discloses the secrets of all higher-level groups the virtual
client is a member of.

## Reuse guard

The guarantee that no two emulator clients select colliding nonces
({{reuse-guard}}) relies on all emulator clients agreeing on `N_e`, on their
leaf indices at epoch `e`, and on the exact PRP instantiation described in
{{small-space-prp}}. The PRP key is 128 bits regardless of the ciphersuites in
use; this bounds the sender-attribution and unlinkability properties of the
reuse guard but does not affect the confidentiality of MLS messages.

Since `reuse_guard_secret` is shared across all higher-level groups for a
given emulation-group epoch, two messages in different higher-level groups
that happen to use the same `key_schedule_nonce` will use the same `prp_key`.
This does not endanger nonce uniqueness, because the two messages are
encrypted under independent keys.

# Privacy Considerations

Using a virtual client masks the emulation group's membership and activity from
other members of higher-level groups: additions, removals, and updates of
emulator clients appear in higher-level groups as ordinary LeafNode updates of
the virtual client, and PrivateMessages sent by different emulator clients are
indistinguishable to other higher-level group members. Whether the identity of
the emulator clients is hidden additionally depends on the design of the
Authentication Service and on the credentials the application provisions for
the virtual client.

The following residual metadata remains observable:

- The presence of a DerivationInfo in a LeafNode reveals to anyone
  with access to the ratchet tree (including a DS that distributes GroupInfo
  or ratchet trees) that the leaf belongs to a virtual client. Applications
  that want to hide which leaves are virtual would need non-virtual clients to
  include indistinguishable components.
- The `epoch_id` in a DerivationInfo is identical across all
  LeafNodes and KeyPackages that the virtual client produces from the same
  emulation-group epoch. Parties with access to the ratchet trees of multiple
  higher-level groups can use it to link the virtual client's leaves across
  those groups, and can observe how often the emulation group commits.
- Generation IDs ({{coordinating-ratchet-generations-with-the-ds}}) are only
  attached by virtual-client senders and therefore identify virtual-client
  traffic to the DS, in addition to revealing how many distinct ratchet
  generations are in use.
- An external commit by a virtual client (Variant B of
  {{adding-an-emulator-client}}, or {{joining-externally}}) is visible to all
  members of the higher-level group as the virtual client leaving and
  re-joining.
- The DerivationInfo ciphertext of a LeafNode with `leaf_node_source` `commit`
  is longer when it carries an `external_init_secret`. Parties with access to
  the ratchet tree, including members who join after the external commit, can
  therefore tell that the virtual client's current leaf was created by an
  external commit rather than a regular Commit, for as long as that leaf
  remains in the tree.

# IANA Considerations

This document requests the addition of a new value under the heading "Messaging
Layer Security" in the "MLS Component Types" registry.

## virtual_clients

The component implementing the virtual client emulation defined in this
document. The component data carried in each location is determined by the
object in which the component appears:

- In GroupInfo objects of the emulation group, the component data is a
  NewEmulatorClientState struct carrying the state a newly added emulator
  client needs to act as the virtual client
  ({{adding-an-emulator-client}}).
- In LeafNode objects of a virtual client, the component data is a
  DerivationInfo struct communicating how to derive the LeafNode's key
  material ({{creating-leafnodes-and-updatepaths}}).
- In SafeAAD objects of Commits in the emulation group, the component data is
  a VirtualClientAction struct communicating which virtual client action is
  taken in conjunction with the Commit ({{virtual-client-actions}}).
- The component ID is additionally used with the Safe Exporter API to export
  the per-epoch `emulator_epoch_secret` from the emulation group
  ({{generating-virtual-client-secrets}}).

The requested registration is:

- Value: 0x0006 (suggested)
- Name: virtual_clients
- Where: GI, LN, AD, ES
- Recommended: Y
