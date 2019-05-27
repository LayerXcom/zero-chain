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

        impl<E: Engine, B: Backend<E>> Synthesizer<E, B> {
            // A * 1 = A
            fn remove_current_variable(&mut self) {
                match self.current_variable.take() {
                    Some(index) => {
                        let var_a = Variable::A(index);
                        let var_b = Variable::B(index);
                        let var_c = Variable::C(index);

                        let mut product = None;

                        let value_a = self.backend.get_var(var_a);

                        self.backend.set_var(var_b, || {
                            let value_b = E::Fr::one();
                            product = Some(value_a.ok_or(SynthesisError::AssignmentMissing)?);
                            product.as_mut().map(|p| p.mul_assign(&value_b));

                            Ok(value_b)
                        }).expect("should exist by now");

                        self.backend.set_var(var_c, || {
                            product.ok_or(SynthesisError::AssignmentMissing)
                        }).expect("should exist by now");

                        self.current_variable = None;
                    },
                    _ => {}
                }
            }
        }

        impl<E: Engine, B: Backend<E>> ConstraintSystem<E> for Synthesizer<E, B> {
            const ONE: Variable = Variable::A(1);

            fn alloc<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                match self.current_variable.take() {
                    Some(index) => {
                        let var_a = Variable::A(index);
                        let var_b = Variable::B(index);
                        let var_c = Variable::C(index);

                        let value_a = self.backend.get_var(var_a).ok_or(SynthesisError::AssignmentMissing)?;
                        let mut product = None;

                        self.backend.set_var(var_b, || {
                            let value_b = value()?;
                            product = Some(value_a);
                            product.as_mut().map(|p| p.mul_assign(&value_b));
                            Ok(value_b)
                        })?;

                        self.backend.set_var(var_c, || {
                            product.ok_or(SynthesisError::AssignmentMissing)
                        })?;

                        self.current_variable = None;
                        Ok(var_b)
                    },
                    None => {
                        self.n += 1;
                        self.backend.new_multiplication_gate();

                        let index = self.n;
                        let var_a = Variable::A(index);

                        self.backend.set_var(var_a, value)?;
                        self.current_variable = Some(index);
                        Ok(var_a)
                    }
                }
            }

            fn alloc_input<F>(&mut self, value: F) -> Result<Variable, SynthesisError>
            where
                F: FnOnce() -> Result<E::Fr, SynthesisError>
            {
                let input_var = self.alloc(value)?;
                self.enforce_zero(LinearCombination::zero() + input_var);

                self.backend.new_k_power(self.q - 2);
                self.backend.new_k_power(self.q - 1);
                self.backend.new_k_power(self.q);

                Ok(input_var)
            }

            fn enforce_zero(&mut self, lc: LinearCombination<E>) {
                self.q += 1;
                self.backend.new_linear_constraint();

                for (var, coeff) in lc.as_ref() {
                    self.backend.insert_coefficient(*var, *coeff);
                }

                self.remove_current_variable();

                {
                    self.q += 1;
                    self.backend.new_linear_constraint();
                    let mut alloc_map = HashMap::with_capacity(lc.as_ref().len());
                    let new_index = self.n + 1;

                    for (var, _) in lc.as_ref() {
                        match var {
                            Variable::A(index) => {
                                if alloc_map.get(index).is_none() && *index != 1 {
                                    alloc_map.insert(*index, new_index);
                                }
                            },
                            Variable::B(index) => {
                                if alloc_map.get(index).is_none() && *index != 2 {
                                    alloc_map.insert(*index, new_index);
                                }
                            },
                            Variable::C(index) => {
                                if alloc_map.get(index).is_none() && *index != 3 {
                                    alloc_map.insert(*index, new_index);
                                }
                            }
                        }
                    }

                    for (index, new_index) in alloc_map.iter() {
                        self.n += 1;
                        self.backend.new_multiplication_gate();

                        let current_value_a = self.backend.get_var(Variable::A(*index));
                        let current_value_b = self.backend.get_var(Variable::B(*index));
                        let current_value_c = self.backend.get_var(Variable::C(*index));

                        self.backend.set_var(Variable::B(*new_index), || {
                            let value = current_value_a.ok_or(SynthesisError::AssignmentMissing)?;
                            Ok(value)
                        });

                        self.backend.set_var(Variable::C(*new_index), || {
                            let value = current_value_b.ok_or(SynthesisError::AssignmentMissing)?;
                            Ok(value)
                        });

                        self.backend.set_var(Variable::A(*new_index), || {
                            let value = current_value_c.ok_or(SynthesisError::AssignmentMissing)?;
                            Ok(value)
                        });
                    }

                    for (var, coeff) in lc.as_ref() {
                        let new_var = match var {
                            Variable::A(index) => {
                                if *index == 1 {
                                    Variable::B(2)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::B(*new_index)
                                }
                            },
                            Variable::B(index) => {
                                if *index == 2 {
                                    Variable::C(3)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::C(*new_index)
                                }
                            },
                            Variable::C(index) => {
                                if *index == 3 {
                                    Variable::A(1)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::A(*new_index)
                                }
                            }
                        };

                        self.backend.insert_coefficient(new_var, *coeff);
                    }
                }

                {
                    self.q += 1;
                    self.backend.new_linear_constraint();

                    let mut alloc_map = HashMap::with_capacity(lc.as_ref().len());
                    let new_index = self.n + 1;

                    for (var, _) in lc.as_ref() {
                        match var {
                            Variable::A(index) => {
                                if alloc_map.get(index).is_none() && *index != 1 {
                                    alloc_map.insert(*index, new_index);
                                }
                            },
                            Variable::B(index) => {
                                if alloc_map.get(index).is_none() && *index != 2 {
                                    alloc_map.insert(*index, new_index);
                                }
                            },
                            Variable::C(index) => {
                                if alloc_map.get(index).is_none() && *index != 3 {
                                    alloc_map.insert(*index, new_index);
                                }
                            }
                        }
                    }

                    for (index, new_index) in alloc_map.iter() {
                        self.n += 1;
                        self.backend.new_multiplication_gate();

                        let current_value_a = self.backend.get_var(Variable::A(*index));
                        let current_value_b = self.backend.get_var(Variable::B(*index));
                        let current_value_c = self.backend.get_var(Variable::C(*index));

                        self.backend.set_var(Variable::A(*new_index), || {
                            current_value_b.ok_or(SynthesisError::AssignmentMissing)
                        }).expect("should exist by now");

                        self.backend.set_var(Variable::B(*new_index), || {
                            current_value_c.ok_or(SynthesisError::AssignmentMissing)
                        }).expect("should exist by now");

                        self.backend.set_var(Variable::C(*new_index), || {
                            current_value_a.ok_or(SynthesisError::AssignmentMissing)
                        }).expect("should exist by now");
                    }

                    for (var, coeff) in lc.as_ref() {
                        let new_var = match var {
                            Variable::A(index) => {
                                if *index == 1 {
                                    Variable::C(3)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::C(*new_index)
                                }
                            },
                            Variable::B(index) => {
                                if *index == 2 {
                                    Variable::A(1)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::B(*new_index)
                                }
                            },
                            Variable::C(index) => {
                                if *index == 3 {
                                    Variable::B(2)
                                } else {
                                    let new_index = alloc_map.get(index).unwrap();
                                    Variable::C(*new_index)
                                }
                            }
                        };

                        self.backend.insert_coefficient(new_var, *coeff);
                    }
                }
            }

            fn multiply<F>(&mut self, values: F) -> Result<(Variable, Variable, Variable), SynthesisError>
            where
                F: FnOnce() -> Result<(E::Fr, E::Fr, E::Fr), SynthesisError>
            {
                self.n += 1;
                self.backend.new_multiplication_gate();
                let index = self.n;

                let var_a = Variable::A(index);
                let var_b = Variable::B(index);
                let var_c = Variable::C(index);

                let mut value_b = None;
                let mut value_c = None;

                self.backend.set_var(var_a, || {
                    let (a, b, c) = values()?;

                    value_b = Some(b);
                    value_c = Some(c);

                    Ok(a)
                })?;

                self.backend.set_var(var_b, || {
                    value_b.ok_or(SynthesisError::AssignmentMissing)
                })?;

                self.backend.set_var(var_c, || {
                    value_c.ok_or(SynthesisError::AssignmentMissing)
                })?;

                Ok((var_a, var_b, var_c))
            }

            fn get_value(&self, var: Variable) -> Result<E::Fr, ()> {
                self.backend.get_var(var).ok_or(())
            }
        }

        let mut instance = Synthesizer {
            backend,
            current_variable: None,
            q: 0,
            n: 0,
            _marker: PhantomData,
        };

        let one = instance.alloc_input(|| {
            Ok(E::Fr::one())
        }).expect("should have no issues");

        match (one, <Synthesizer<E, B> as ConstraintSystem<E>>::ONE) {
            (Variable::A(1), Variable::A(1)) => {},
            _ => panic!("one variable is incorrect")
        }

        circuit.synthesize(&mut instance)?;

        Ok(())
    }
}
