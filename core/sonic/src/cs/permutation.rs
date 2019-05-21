use std::marker::PhantomData;
use std::collections::HashMap;
use pairing::Engine;
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
                self.q += 1;
                self.backend.new_linear_constraint();

                for (var, coeff) in lc.as_ref() {
                    self.backend.insert_coefficient(*var, *coeff);
                }

                // purge current variable
                {
                    self.q += 1;
                    self.backend.new_linear_constraint();

                    let mut alloc_map = HashMap::with_capacity(lc.as_ref().len());
                    let mut expected_new_index = self.n + 1;

                    // determine size of the map
                    for (var, _) in lc.as_ref() {
                        match var {
                            Variable::A(index) => {
                                if alloc_map.get(index).is_none() && *index != 1 {
                                    alloc_map.insert(*index, expected_new_index);
                                    expected_new_index += 1;
                                }
                            },
                            Variable::B(index) => {
                                if alloc_map.get(index).is_none() && *index != 2 {
                                    alloc_map.insert(*index, expected_new_index);
                                    expected_new_index += 1;
                                }
                            },
                            Variable::C(index) => {
                                if alloc_map.get(index).is_none() && *index != 3 {
                                    alloc_map.insert(*index, expected_new_index);
                                    expected_new_index += 1;
                                }
                            }
                        }

                        for _ in 0..alloc_map.len() {
                            self.backend.new_multiplication_gate();
                            self.n += 1;
                        }

                        for (index, new_index) in alloc_map.iter() {
                            let var_a = Variable::A(*new_index);
                            let var_b = Variable::B(*new_index);
                            let var_c = Variable::C(*new_index);

                            let b_value = self.backend.get_var(Variable::A(*index));
                            let c_value = self.backend.get_var(Variable::B(*index));
                            let a_value = self.backend.get_var(Variable::C(*index));

                            self.backend.set_var(var_a, || {
                                let value = a_value.ok_or(SynthesisError::AssignmentMissing)?;
                                Ok(value)
                            }).expect("should exist by now");

                            self.backend.set_var(var_b, || {
                                let value = b_value.ok_or(SynthesisError::AssignmentMissing)?;
                                Ok(value)
                            }).expect("should exist by now");

                            self.backend.set_var(var_c, || {
                                let value = c_value.ok_or(SynthesisError::AssignmentMissing)?;
                                Ok(value)
                            }).expect("should exist by now");
                        }

                        for (var, coeff) in lc.as_ref() {
                            let new_var = match var {
                                Variable::A(index) => {
                                    let var = if *index == 1 {
                                        Variable::B(2)
                                    } else {
                                        let new_index = alloc_map.get(index).unwrap();
                                        Variable::B(*new_index)
                                    };

                                    var
                                },
                                Variable::B(index) => {
                                    let var = if *index == 2 {
                                        Variable::C(3)
                                    } else {
                                        let new_index = alloc_map.get(index).unwrap();
                                        Variable::C(*new_index)
                                    };

                                    var
                                },
                                Variable::C(index) => {
                                    let var = if *index == 3 {
                                        Variable::A(1)
                                    } else {
                                        let new_index = alloc_map.get(index).unwrap();
                                        Variable::A(*new_index)
                                    };

                                    var
                                }
                            };

                            self.backend.insert_coefficient(new_var, *coeff);
                        }
                    }
                }

                // {
                //     self.q += 1;
                //     self.backend.new_linear_constraint();

                //     let mut alloc_map = HashMap::with_capacity(lc.as_ref().len());
                //     let mut expected_new_index = self.n + 1;

                //     // determine size of the map
                //     for (var, _) in lc.as_ref() {
                //         match var {
                //             Variable::A(index) => {
                //                 if alloc_map.get(index).is_none() && *index != 1 {

                //                 }
                //             }
                //         }
                //     }
                }

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
