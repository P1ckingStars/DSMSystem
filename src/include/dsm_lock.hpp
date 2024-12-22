
#ifndef DSM_LOCK_HPP
#define DSM_LOCK_HPP

namespace dsm {

typedef int dsm_mutex;

void dsm_mutex_lock(dsm_mutex * mu);
void dsm_mutex_unlock(dsm_mutex * mu);

}

#endif
