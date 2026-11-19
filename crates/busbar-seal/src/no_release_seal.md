Without the dev-only `test-seal` feature (every release build) the test constructors do not exist:

```compile_fail,E0599
let _forged = busbar_seal::KernelSeal::acquire_for_kernel();
```

```compile_fail,E0599
let _forged = busbar_seal::SlotSeal::acquire_for_tests();
```

and the seals' fields are private, so the free functions are the only way to one:

```compile_fail,E0423
let _forged = busbar_seal::KernelSeal(());
```

```compile_fail,E0423
let _forged = busbar_seal::SlotSeal(());
```
