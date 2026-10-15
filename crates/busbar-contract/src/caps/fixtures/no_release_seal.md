```compile_fail,E0599
use busbar_contract::caps::KernelSeal;
let _forged = KernelSeal::acquire_for_kernel();
```
