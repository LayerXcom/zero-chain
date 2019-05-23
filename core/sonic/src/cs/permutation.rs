use std::marker::PhantomData;
use std::collections::HashMap;
use pairing::{Engine, Field};
use bellman::SynthesisError;
use super::{SynthesisDriver, Circuit, Backend, ConstraintSystem, Variable, LinearCombination};

pub struct Permutation;

impl SynthesisDriver for Permutation {
    fn synthesize<E: Engine, C: Circuit<E>, B: Backend<E>>(backend: B, circuit: &C) -> Result<(), SynthesisError> {
        struct Synthesizer<E: Engine, B: Backend<E>> {
            backend: B,
            current_variable: Option<usize>,
            q: usize,
            n: usize,
            _marker: PhantomData<E>,
        }

        // impl<E: Engine, B: Backend<E>> Synthesizer<E, B> {
        //     // A * 1 = A
        //     fn remove_current_variable(&mut self) {
        //         match self.current_variable.take() {
        //             Some(index) => {
        //                 let var_a = Variable::A(index);
        //                 let var_b = Variable::B(index);
        //                 let var_c = Variable::C(index);

        //                 let mut product = E::Fr::zero();

        //                 let value_a = self.backend.get_var(var_a);

        //                 self.backend.set_var(var_b, || {
        //                     let value_b = E::Fr::one();
        //                     product.add_assign(&)
        //                 });
        //             },
        //             _ => {}
        //         }
        //     }
        // }

        impl<E: Engine, B: Backend<E>> ConstraintSystem<E> for Synthesizer<E, B> {
            const ONE: Variable = Variable::A(1);

            fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                unimplemented!();
            }

            fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                unimplemented!();
            }

            fn enforce_zero(&mut self, lc: LinearCombination<E>) {


                unimplemented!();
            }

            fn multiply<F>(&mut self, values: F) -> Result<(Variable, Variable, Variable), SynthesisError>
            where
                F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>
            {
                unimplemented!();
            }

            fn get_value(&self, var: Variable) -> Result<E::Fr, ()> {
                unimplemented!();
            }
        }

        Ok(())
    }
}
