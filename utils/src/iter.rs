use itertools::{EitherOrBoth, Itertools};

use super::try_iter::{try_pair_with_slice, try_validate_pairs, IndexIsOutOfBounds, InvalidPair};

/// Plucks items from the supplied iterator corresponding to missed indices.
/// This function implies that both iterators are sorted.
pub fn pluck_missed<Indices, Iter>(indices: Indices, iter: Iter) -> impl Iterator<Item = Iter::Item>
where
    Indices: IntoIterator<Item = usize>,
    Iter: IntoIterator,
{
    iter.into_iter()
        .enumerate()
        .merge_join_by(indices, |(i, _), j| i.cmp(j))
        .filter_map(|either| match either {
            EitherOrBoth::Left((_, item)) => Some(item),
            _ => None,
        })
}

/// Maps supplied iterator and attempts to pair each item with an item from the slice which has provided index.
/// Returns `Err` containing an invalid index in case slice length is exceeded.
pub fn pair_with_slice<'iter, 'pairs, I, Item, P>(
    iter: I,
    pairs: &'pairs [P],
) -> impl Iterator<Item = Result<(&'pairs P, Item), IndexIsOutOfBounds>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: 'iter,
{
    try_pair_with_slice(iter.into_iter().map(Ok), pairs)
}

/// Trait allowing to validate supplied pair.
/// Prior to validation, each item must be mapped using `PairValidator::map`.
pub trait PairValidator<I> {
    /// Item to be used in validation.
    type MappedItem;

    /// Maps an item to prepare it for validation.
    fn map(&self, item: &I) -> Self::MappedItem;

    /// Validates given pair.
    fn validate(&mut self, previous: &Self::MappedItem, current: &Self::MappedItem) -> bool;
}

impl<I, M, MapF, ValidateF> PairValidator<I> for (MapF, ValidateF)
where
    MapF: Fn(&I) -> M,
    ValidateF: FnMut(&M, &M) -> bool,
{
    type MappedItem = M;

    fn map(&self, item: &I) -> M {
        self.0(item)
    }

    fn validate(&mut self, previous: &M, current: &M) -> bool {
        self.1(previous, current)
    }
}

impl<I: Clone, ValidateF> PairValidator<I> for ValidateF
where
    ValidateF: FnMut(&I, &I) -> bool,
{
    type MappedItem = I;

    fn map(&self, item: &I) -> I {
        item.clone()
    }

    fn validate(&mut self, previous: &I, current: &I) -> bool {
        (self)(previous, current)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current left items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckLeft<F>(pub F);

impl<First: Clone, Second, ValidateF> PairValidator<(First, Second)> for CheckLeft<ValidateF>
where
    ValidateF: FnMut(&First, &First) -> bool,
{
    type MappedItem = First;

    fn map(&self, item: &(First, Second)) -> First {
        item.0.clone()
    }

    fn validate(&mut self, previous: &First, current: &First) -> bool {
        self.0(previous, current)
    }
}

/// Implements `PairValidator` which ensures that for each previous - current right items pairs satisfy provided function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckRight<F>(pub F);

impl<First, Second: Clone, ValidateF> PairValidator<(First, Second)> for CheckRight<ValidateF>
where
    ValidateF: FnMut(&Second, &Second) -> bool,
{
    type MappedItem = Second;

    fn map(&self, item: &(First, Second)) -> Second {
        item.1.clone()
    }

    fn validate(&mut self, previous: &Second, current: &Second) -> bool {
        self.0(previous, current)
    }
}

/// Maps supplied iterator and attempts to pair each successfully validated item with a corresponding item from the slice.
/// Validation errors will be propagated without looking at them.
/// In case of error, `Err(IndexIsOutOfBounds)` will be emitted.
pub fn pair_valid_pairs_with_slice<'iter, 'pairs, I, Item, Pair, E, P>(
    iter: I,
    validator: P,
    pairs: &'pairs [Pair],
) -> impl Iterator<Item = Result<(&'pairs Pair, Item), E>> + 'iter
where
    'pairs: 'iter,
    I: IntoIterator<Item = (usize, Item)> + 'iter,
    Item: Clone + 'iter,
    P: PairValidator<(usize, Item)> + 'iter,
    E: From<IndexIsOutOfBounds> + From<InvalidPair<P::MappedItem>> + 'iter,
{
    try_pair_with_slice(
        try_validate_pairs(iter.into_iter().map(Ok), validator),
        pairs,
    )
}

/// Ensures that the given iterator satisfies provided function for each previous - current pair.
/// The supplied option will be modified to invalid pair in case of failure, and iteration will be aborted.
pub fn take_while_pairs_satisfy<'iter, 'invalid, I, P>(
    iter: I,
    validator: P,
    invalid_pair: &'invalid mut Option<(P::MappedItem, P::MappedItem)>,
) -> impl Iterator<Item = I::Item> + 'iter
where
    'invalid: 'iter,
    I: IntoIterator + 'iter,
    P: PairValidator<I::Item> + 'iter,
{
    try_validate_pairs(iter.into_iter().map(Ok), validator)
        .map(|res| {
            res.map_err(InvalidPair::into)
                .map_err(|invalid| invalid_pair.replace(invalid))
                .ok()
        })
        .take_while(Option::is_some)
        .flatten()
}

/// Skips up to `n` elements from the iterator using supplied random generator.
pub fn skip_up_to_n<'rng, I>(
    rng: &'rng mut impl ark_std::rand::RngCore,
    iter: I,
    mut allowed_to_skip: usize,
) -> impl Iterator<Item = I::Item> + 'rng
where
    I: IntoIterator + 'rng,
{
    iter.into_iter().filter(move |_| {
        use ark_std::rand::Rng;

        let res = allowed_to_skip == 0 || rng.gen_bool(0.5);
        if !res {
            allowed_to_skip -= 1;
        }

        res
    })
}
