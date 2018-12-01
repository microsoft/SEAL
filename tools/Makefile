# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

SHELL=/bin/bash
COMPR_SYSTEM_INFO_ARCHIVE=../system_info.tar.gz

.PHONY: system_info clean

system_info: clean $(COMPR_SYSTEM_INFO_ARCHIVE)

$(COMPR_SYSTEM_INFO_ARCHIVE): scripts/collect_system_info.sh
	@$(SHELL) scripts/collect_system_info.sh

clean:
	@rm -f $(COMPR_SYSTEM_INFO_ARCHIVE)
