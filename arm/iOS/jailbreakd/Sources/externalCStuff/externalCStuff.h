//
//  externalCStuff.h
//  jailbreakd - externalCStuff
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

#ifndef externalCStuff_h
#define externalCStuff_h

#include <sys/snapshot.h>
#include <spawn.h>

#ifdef IOS_BUILD
#include "hfs_mount.h"
#include "CFUserNotification.h"
#endif

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    uint32_t          error;
    attrreference_t   name_info;
    char              *name;
    fsobj_type_t      obj_type;
} val_attrs_t;

int     posix_spawnattr_set_persona_np(const posix_spawnattr_t * __restrict, uid_t, uint32_t);
int     posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t * __restrict, uid_t);
int     posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t * __restrict, gid_t);

#endif /* externalCStuff_h */
