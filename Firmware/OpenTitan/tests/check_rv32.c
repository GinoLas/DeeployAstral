#include "../deeploy_ot_async_task.h"
#include "../deeploy_ot_platform.h"
uint32_t check_primitives(void) {
  uint32_t state = ot_irq_save();
  ot_fence();
  ot_irq_restore(state);
  return sizeof(deeploy_ot_task_t);
}
