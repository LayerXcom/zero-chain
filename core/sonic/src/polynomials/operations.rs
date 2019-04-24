use bellman::multicore::Worker;
use bellman::SynthesisError;
use bellman::domain::{EvaluationDomain, Scalar};
use pairing::{Engine, Field};
use clear_on_drop::clear::Clear;

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

pub fn mul_polynomials<E: Engine>(a: &[E::Fr], b: &[E::Fr]) -> Result<Vec<E::Fr>, SynthesisError> {
    let res_len = a.len() + b.len() - 1;

    let worker = Worker::new();
    let scalars_a = a.iter().map(|e| Scalar::<E>(*e)).collect();
    // the size of evaluation domain is polynomial's multiplied by other.
    let mut domain_a = EvaluationDomain::from_coeffs_into_sized(scalars_a, res_len)?;

    let scalars_b = b.iter().map(|e| Scalar::<E>(*e)).collect();
    let mut domain_b = EvaluationDomain::from_coeffs_into_sized(scalars_b, res_len)?;

    // Convert to point-value representations
    domain_a.fft(&worker);
    domain_b.fft(&worker);

    // Perform O(n) multiplication of two polynomials in the domain.
    domain_a.mul_assign(&worker, &domain_b);
    drop(domain_b);

    // Convert back to point-value representations
    domain_a.ifft(&worker);

    let mut mul_res: Vec<E::Fr> = domain_a.into_coeffs().iter().map(|e| e.0).collect();
    mul_res.truncate(res_len);

    Ok(mul_res)
}
