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
operation in the emulation group to all virtual clients emulated in that group.

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
Welcome carries a NewEmulatorClientState component that provides the state the
joining emulator client needs to act as the virtual client going forward.

How the joining emulator client subsequently becomes an active participant in
each higher-level group is application-defined. This document specifies two
variants that the provisioning emulator client MAY use on a per-group basis:

- **Variant A (provisioning state transfer).** The provisioning emulator client
  includes, for each higher-level group, the key-schedule outputs of the current
  epoch together with the HPKE private keys on the virtual client's direct path.
  The joining emulator obtains the RatchetTree and the GroupContext from an
  application-defined source. It then decrypts any in-flight traffic, applies
  any intervening commit, and then sends its own Commit with an update path to
  move that group to a fresh epoch.
- **Variant B (external commit).** The provisioning emulator client only
  identifies which higher-level groups the virtual client is in. The joining
  emulator client acquires each group's current GroupInfo (from the DS or some
  other application-defined source) and performs an external commit into the
  group, evicting the virtual client's prior membership via a self-Remove
  proposal.

Applications MAY mix the two variants across groups, for example using
Variant A for groups where metadata hiding matters and Variant B elsewhere.

### Trade-offs

- **Observability.** Variant A produces an ordinary Commit that looks like
  any other key rotation to the rest of the higher-level group. Variant B
  appears as the virtual client leaving and re-joining, which is visible to
  every member and may undermine metadata-hiding goals.
- **Forward secrecy.** Variant A chains the new epoch from the previous epoch's
  `init_secret`. Variant B breaks the commit chain resulting in weaker forward
  secrecy at the point of onboarding.
- **Policy.** Some applications may restrict external commits by policy leaving
  Variant A as only option.
- **State transfer cost.** Variant A requires O(log N) HPKE private keys and the
  current epoch's key-schedule state per higher-level group. Depending on group
  size and the group's ciphersuite, this may exceed the application's
  performance constraints. Variant B's overhead is constant per group.

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
  opaque random<V>;
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
  (255)
} SecretTreeRatchetType;

struct {
  uint32 leaf_index;
  SecretTreeRatchetType ratchet_type;
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
  opaque random<V>;
} KeyPackageDerivationInfo;

struct {
  opaque epoch_id<V>;
  PPRFState epoch_base_secret;
  opaque epoch_encryption_key<V>;
  opaque generation_id_secret<V>;
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
- `RetainedOperationSecret` carries an `operation_secret` whose PPRF input has
  been punctured, but whose derived key material is still live. Entries are
  identified by `(epoch_id, operation_type, leaf_index, random)`.
- `SecretTreeState` serializes the retained state of an RFC 9420 Secret Tree.
  Each `SecretTreeNodeState` contains an unexpanded tree node secret and its
  RFC 9420 tree node index. Each `SecretTreeRatchetState` contains the current
  state of a derived per-leaf hash ratchet; `next_secret` is the ratchet secret
  that will be used to derive the secret for `generation`. The serialized state
  MUST contain exactly the retained secrets needed to continue the Secret Tree
  deletion schedule from the sender's current state and MUST NOT contain
  secrets that have already been deleted.
- `signing_key_material` is an application-defined blob that conveys whatever
  signing-key state the joining emulator client needs. For configurations
  where signing keys are derived from emulation-group secrets, it MAY be
  zero-length. See {{generating-virtual-client-secrets}}.
- `active_key_packages` lists every KeyPackage the virtual client has
  outstanding. Each entry carries the KeyPackageRef together with the
  identifiers needed to find the corresponding retained `key_package`
  operation secret. When a Welcome arrives encrypted to one of these
  KeyPackages, the joining emulator client identifies the entry by
  KeyPackageRef, finds the `RetainedOperationSecret` matching `(epoch_id,
  key_package, leaf_index, random)`, and uses its `operation_secret` to derive
  the corresponding `init_key`.
- `retained_operation_secrets` contains every punctured `operation_secret`
  whose derived key material is still live. This includes operation secrets
  for outstanding KeyPackages, for the current LeafNode of each higher-level
  group, and for sent but uncommitted LeafNodes or UpdatePaths.
- `past_emulation_epochs` carries, for every emulation-group epoch still
  referenced by an active LeafNode, KeyPackage, or retained operation secret
  and not equal to the current epoch, the punctured `epoch_base_secret` PPRF
  state, the `epoch_encryption_key`, and the `generation_id_secret`. State for
  the current emulation-group epoch is not included here because the joining
  emulator client derives it from the emulation group's Welcome.
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
      application-ratchet keys needed to decrypt in-flight
      PrivateMessages.
    - `safe_exporter_tree` is the current punctured state of the Safe
      Exporter API's Exporter Tree if the higher-level group uses that API.
      If the group does not use the Safe Exporter API, `nodes` is
      zero-length. When used for a Safe Exporter Tree, `PPRFState` paths are
      16-bit paths indexed by `ComponentID`.
    - `direct_path_private_keys` is the list of HPKE private keys for each
      non-blank node in the virtual client's filtered direct path. The first
      entry is the private key for the parent of the virtual client's leaf,
      if that node is non-blank. Subsequent entries correspond to the next
      non-blank nodes on the direct path toward the root, in order. The
      virtual client's leaf private key itself is derivable from the
      corresponding retained `leaf_node` operation secret identified by the
      DerivationInfoComponent on the current LeafNode and is therefore not
      transferred explicitly.

  For `external_commit` entries, no additional per-group fields are
  included. The joining emulator client external-commits into the group —
  fetching the current GroupInfo from the DS or another application-defined
  source — and includes a Remove proposal for the virtual client's prior leaf
  to evict the old membership.

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

To effectively remove an emulator client, it needs to be removed from the
emulation group _and_ a Commit with an update path needs to be sent into every
higher level group by another emulator client using the new emulation group's
epoch to generate the necessary secrets (see
{{generating-virtual-client-secrets}}). The latter step is required to ensure
that the removed emulator client loses its access to any active virtual client
secrets.

A corollary of this slightly more elaborate removal procedure is that the
removal of an emulator client requires another emulator client to be online and
perform the necessary updates. This is in contrast to the simple multi-client
setup, where an external sender can effectively remove individual clients.

# Client emulation

To ensure that all emulator clients can act through the virtual client, they
have to coordinate some of its actions.

## Delivery Service

Client emulation requires that any message sent by an emulator client on behalf
of a virtual client be delivered not just to the rest of the higher-level group
to which the message is sent, but also to all other clients in the emulation
group.

## Generating Virtual Client Secrets

Generally, secrets for virtual client operations are derived from the emulation
group. To that end, emulator clients derive an `epoch_base_secret` with every
new epoch of that group.

~~~
emulator_epoch_secret = SafeExportSecret(XXX)
~~~

TODO: Replace XXX with the component ID.

The `emulator_epoch_secret` is in turn used to derive four further secrets, after
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
~~~

The `epoch_base_secret` is then used to key an instance of the PPRF defined in
{{!I-D.ietf-mls-extensions}} using a tree with `2^32` leaves.

Secrets are derived from the PPRF as follows:

~~~
VirtualClientSecret(Input) = tree_node_[LeafNode(Input)]_secret
~~~

Emulator clients MUST store the `epoch_id`, `epoch_encryption_key`,
`generation_id_secret`, and punctured `epoch_base_secret` until no key material
derived from the epoch is actively used anymore. This is required for the
addition of new clients to the emulation group as described in
{{adding-an-emulator-client}}.

When deriving a secret for a virtual client, e.g. for use in a KeyPackage or
LeafNode update, the deriving client chooses a `VirtualClientOperationType`,
samples a random octet string `random`, and hashes it with its leaf index in the
emulation group using the hash function of the emulation group's ciphersuite.
The `operation_type` is `key_package` when creating a KeyPackage and `leaf_node`
when creating a LeafNode for an Update proposal, a Commit with an update path,
or an external commit. Applications MAY use the operation type `application` to
derive application-specific key material.

~~~
struct {
  uint32 leaf_index;
  VirtualClientOperationType operation_type;
  opaque random<V>;
} HashInput

pprf_input = Hash(HashInput)
~~~

The `pprf_input` is then used to derive an `operation_secret`.

~~~
operation_secret = VirtualClientSecret(pprf_input)
~~~

After deriving `operation_secret`, the emulator client MUST puncture
`pprf_input` from the PPRF state for the corresponding `epoch_base_secret`.
The emulator client MUST retain `operation_secret` as a
RetainedOperationSecret until all key material derived from it is no longer
active, and MUST delete `operation_secret` after that point.

Given an `epoch_id`, `operation_type`, `random`, and the `leaf_index` of the
emulator client performing the virtual client operation, other emulator
clients can derive the `operation_secret`, puncture the same `pprf_input`, and
use the `operation_secret` to perform the same operation. If the PPRF input has
already been punctured, for example because the emulator client joined after
the operation took place, the emulator client uses the corresponding
RetainedOperationSecret transferred in NewEmulatorClientState.

Depending on the operation, the acting emulator client will have to derive one
or more secrets from the `operation_secret`.

There are five types of MLS-related secrets that can be derived from an
`operation_secret`.

- `signature_key_secret`: Used to derive the signature key in a virtual client's
  leaf
- `init_key_secret`: Used to derive the `init_key` HPKE key in a KeyPackage
- `encryption_key_secret`: Used to derive the `encryption_key` HPKE key in the
  LeafNode of a virtual client
- `path_generation_secret`: Used to generate `path_secret`s for the UpdatePath
  of a virtual client
- `reuse_guard_secret`: Used to derive the PRP key for `reuse_guard` values when
  the virtual client sends a PrivateMessage (see {{reuse-guard}})

~~~
signature_key_secret =
  DeriveSecret(operation_secret, "Signature Key")

encryption_key_secret =
  DeriveSecret(operation_secret, "Encryption Key")

init_key_secret =
  DeriveSecret(operation_secret, "Init Key")

path_generation_secret =
  DeriveSecret(operation_secret, "Path Generation")

reuse_guard_secret =
  DeriveSecret(operation_secret, "Reuse Guard")
~~~

The first four secrets are used as the randomness required in the corresponding
key generation process. `reuse_guard_secret` is used as described in
{{reuse-guard}}.

The source of the virtual client's signature key is application-defined. An
application MAY use `signature_key_secret` to derive a fresh signing key per
operation, or MAY provide signing-key material through other means, for
example a per-group or global signing key issued by the Authentication
Service, or a signing key derived from an emulation-group epoch secret.
Whatever the choice, the `signing_key_material` field of
NewEmulatorClientState (see {{adding-an-emulator-client}}) carries the
state a new emulator client needs; its contents are application-defined.

## Creating LeafNodes and UpdatePaths

When creating a LeafNode, either for a Commit with path, an Update proposal or a
KeyPackage, the creating emulator client MUST derive the necessary secrets from
the current epoch of the emulation group as described in Section
{{generating-virtual-client-secrets}}.

Similarly, if an emulator client generates a Commit with an update path, it
MUST use `path_generation_secret` as the `path_secret` for the first
`parent_node` instead of generating it randomly.

To signal to other emulator clients which epoch to use to derive the necessary
secrets to recreate the key material, the emulator client includes a
DerivationInfoComponent in the LeafNode.

~~~ tls
struct {
  opaque epoch_id<V>;
  opaque ciphertext<V>;
} DerivationInfoComponent

struct {
  uint32 leaf_index;
  opaque random<V>;
} DerivationInfoTBE
~~~

The `ciphertext` is the serialized DerivationInfoTBE encrypted under the epoch's
`epoch_encryption_key` with the `epoch_id` as AAD using the AEAD scheme of the
emulation group's ciphersuite.

When other emulator clients receive a LeafNode update (i.e. either an Update
proposal or a Commit with an UpdatePath) in a higher-level group that the
virtual client is a member of, they use the `epoch_id` to determine the epoch
of the emulation group from which to derive the secrets necessary to re-create
the key material of the LeafNode and potential UpdatePath. The PPRF input is
computed with `operation_type` set to `leaf_node`.

## Virtual client actions

There are two occasions where emulator clients need to communicate directly to
operate the virtual client. In both cases, the acting emulator client sends a
Commit to the emulation group before taking an action with the virtual client.

The Commit serves two purposes: First, the agreement on message ordering
facilitated by the DS prevents concurrent conflicting actions by two or more
emulator clients. Second, the acting emulator client can attach additional
information to the Commit using the SafeAAD mechanism described in
{{Section 4.9 of !I-D.ietf-mls-extensions}}.

~~~ tls
enum {
  reserved(0),
  key_package_upload(1),
  external_join(2),
  255,
} ActionType;

struct {
  ActionType action_type;
  select (VirtualClientAction.action_type) {
    case key_package_upload:
      KeyPackageUpload key_package_upload;
    case external_join:
      ExternalJoin external_join;
  };
} VirtualClientAction;
~~~

### Creating and uploading KeyPackages

When creating a KeyPackage, the creating emulator client derives the
`init_key_secret` as described in {{generating-virtual-client-secrets}}.

Before uploading one or more KeyPackages for a virtual client, the uploading
emulator client MUST create a KeyPackageUpload message and send it to the
emulation group as described in {{virtual-client-actions}}.

The recipients can use the `leaf_index` of the sender, `operation_type`
`key_package`, the `random`, and `epoch_id` to derive the `init_key` for each
KeyPackageRef. If the recipients receive a Welcome, they can then check which
`init_key` to use based on the KeyPackageRef.

~~~ tls
struct {
  KeyPackageRef key_package_ref<V>;
  opaque random<V>;
} KeyPackageInfo

struct {
  opaque epoch_id<V>;
  KeyPackageInfo key_package_info<V>;
} KeyPackageUpload
~~~

After successfully sending the message, the sender MUST then upload the
corresponding KeyPackages.

The `key_package_refs` allow emulator clients to identify which KeyPackage to
use and how to derive it when the virtual client receives a Welcome message.

### Externally joining groups with the virtual client

Before an emulator client uses an external commit to join a group with the
virtual client, it MUST send an ExternalJoin message to the emulation group as
described in {{virtual-client-actions}}.

~~~ tls
struct {
  opaque group_id<V>;
} ExternalJoin
~~~

The sender MUST then use an external join to join the group with group ID
`group_id`. When creating the Commit to join the group externally, it MUST
generate the LeafNode and path as described in
{{creating-leafnodes-and-updatepaths}}.

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

This document uses the FF1 mode from {{NIST}} with the input-output space of
32-bit integers, instantiated with AES-128.

~~~
output = SmallSpacePRP.Encrypt(key, input)
input = SmallSpacePRP.Decrypt(key, output)
~~~

### Reuse Guard

MLS clients typically generate the bytes for the `reuse_guard` randomly. When
sending a message with a virtual client, however, emulator clients choose a
random value `x` such that `x` modulo the number of leaves in the emulation
group is equal to its `leaf_index`. They then calculate:

~~~
prp_key = ExpandWithLabel(reuse_guard_secret, "reuse guard",
                          key_schedule_nonce, 16)
reuse_guard = SmallSpacePRP.Encrypt(prp_key, x)
~~~

ExpandWithLabel is computed with the emulation group's ciphersuite's algorithms.
`reuse_guard_secret` is derived as described in
{{generating-virtual-client-secrets}} from the `operation_secret` of the
operation that produced the virtual client's currently active LeafNode in the
higher-level group. `key_schedule_nonce` is the nonce provided by the key
schedule for encrypting this message.

`prp_key` is computed in a way that it is unique to the key-nonce pair and
computable by all emulator clients (but nobody else). `reuse_guard` is computed
in a way that it appears random to outside observers (in particular, it does not
leak which emulator client sent the message), but two emulator clients will
never generate the same value.

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
generation ID is derived as follow.

~~~ tls
enum {
  reserved(0),
  application(1),
  handshake(2),
  (255)
} RatchetType

struct {
  uint32 generation;
  RatchetType ratchet_type;
} PrivateMessageContext

generation_id = ExpandWithLabel(generation_id_secret, "generation id",
                      PrivateMessageContext, Kdf.Nh)
~~~

- `generation` is the generation of the ratchet used for encryption
- `ratchet_type` is the type of ratchet used to encrypt the PrivateMessage
- ExpandWithLabel as defined in {{!RFC9420}}
- `generation_id_secret` is derived as specified in
  {{generating-virtual-client-secrets}}
- `Kdf.Nh` is from the emulation group's ciphersuite

Attaching the generation ID to the PrivateMessage allows the DS to detect
collisions between generations per epoch and per ratchet type.

Alternatively, devices communicating with an eventually-consistent DS may need
to simply retain messages and encryption keys for a short period of time after
sending, in case it becomes necessary to decrypt another device's message and
re-encrypt and re-send their original message with another encryption key.

# Security considerations

TODO: Detail security considerations once the protocol has evolved a little
more. Starting points:

Some of the performance benefits of this scheme depend on the fact that one can
update once in the emulation group and “re-use” the new randomness for updates
in multiple higher-level groups. At that point, clients only really recover when
they update the emulation group, i.e. re-using somewhat old randomness of the
emulation group won’t provide real PCS in higher-level groups.

# Privacy considerations

TODO: Specify the metadata hiding properties of the protocol. The details depend
on how we solve some of the problems described throughout this document.
However, using a virtual client should mask add/remove activity in the
underlying emulation group. If it actually hides the identity of the members may
depend on the details of the AS, as well as how we solve the application
messages problem.

# IANA considerations

This document requests the addition of a new value under the heading "Messaging
Layer Security" in the "MLS Component Types" registry.

## DerivationInfoComponent

A component meant to communicate information on how to derive secrets for a
given commit.

- Value: TBD
- Name: DerivationInfoComponent
- Where: LN
- Recommended: True

## VirtualClientAction

A component meant to communicate which virtual client action is taken in
conjunction with the given commit in the emulation group.

- Value: TBD
- Name: VirtualClientAction
- Where: Ad
- Recommended: True
