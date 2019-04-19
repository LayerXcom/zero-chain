use bellman::multicore::Worker;
use pairing::{Engine, Field};

pub fn add_polynomials<E: Engine>(a: &mut [E::Fr], b: &[E::Fr]) {
    assert_eq!(a.len(), b.len());

    let worker = Worker::new();

    worker.scope(a.len(), |scope, chunk| {
        for (a, b) in a.chunks_mut(chunk).zip(b.chunks(chunk)) {
            scope.spawn(move |_| {
                for (a, b) in a.iter_mut().zip(b.iter()) {
                    a.add_assign(b);
                }
            });
        }
    });
}
