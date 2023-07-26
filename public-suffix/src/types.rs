/// Implementation to allow the use of custom tables.
///
/// DO NOT IMPLEMENT THIS MANUALLY. This should only be implemented by the code generator where you
/// feed it the list you want. This list should be formatted in the same way as
/// <https://publicsuffix.org/list/public_suffix_list.dat> where a single line is either:
/// * A domain public suffix,
/// * A comment which starts with `//`,
/// * or empty.
#[allow(missing_docs)]
pub trait Table {
    const NODES_BITS_CHILDREN: u32;
    const NODES_BITS_ICANN: u32;
    const NODES_BITS_TEXT_OFFSET: u32;
    const NODES_BITS_TEXT_LENGTH: u32;

    const CHILDREN_BITS_WILDCARD: u32;
    const CHILDREN_BITS_NODE_TYPE: u32;
    const CHILDREN_BITS_HI: u32;
    const CHILDREN_BITS_LO: u32;

    const NODE_TYPE_NORMAL: u32;
    const NODE_TYPE_EXCEPTION: u32;

    /// numTLD is the number of top level domains.
    const NUM_TLD: u32;

    /// The resulting string is the combined text of all labels concatenated together.
    const TEXT: &'static str;

    /// NODES is the list of nodes. Each node is represented as a uint32, which
    /// encodes the node's children, wildcard bit and node type (as an index into
    /// the children array), ICANN bit and text.
    ///
    /// If the table was generated with the -comments flag, there is a //-comment
    /// after each node's data. In it is the nodes-array indexes of the children,
    /// formatted as (n0x1234-n0x1256), with * denoting the wildcard bit. The
    /// nodeType is printed as + for normal, ! for exception, and o for parent-only
    /// nodes that have children but don't match a domain label in their own right.
    /// An I denotes an ICANN domain.
    const NODES: &'static [u32];

    /// children is the list of nodes' children, the parent's wildcard bit and the
    /// parent's node type. If a node has no children then their children index
    /// will be in the range [0, 6), depending on the wildcard bit and node type.
    const CHILDREN: &'static [u32];
}
