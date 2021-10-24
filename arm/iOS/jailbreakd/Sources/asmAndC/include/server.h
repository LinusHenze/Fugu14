//
//  server.h
//  iDownload
//
//  Created by Linus Henze on 2020-02-09.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

#ifndef server_h
#define server_h

#define VERSION       "1.2"

#define FILE_EXISTS(file) (access(file, F_OK ) != -1)

void launchCServer(void);
void update_springboard_plist(void);

#endif /* server_h */
