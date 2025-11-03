include config.mk

MKDIR = @mkdir -p
MKDIR_TAR = $(MKDIR) $(dir $@)

all: $(CLI_OUT)

$(CLI_OUT): $(CLI_OBJS) $(STATIC_LIB_OUT)
	@$(quiet_LD)
	$(MKDIR_TAR)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(CLI_OBJS) $(STATIC_LIB_OUT)

$(STATIC_LIB_OUT): $(LIB_OBJS) | $(BUILDDIR)
	@$(quiet_AR)
	$(MKDIR_TAR)
	$(Q)$(AR) rcs $@ $(LIB_OBJS)

$(BUILDDIR)/%.o: $(ROOTDIR)/%.c
	@$(quiet_CC)
	$(MKDIR_TAR)
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(Q)rm -rf $(BUILDDIR)

.PHONY: all clean
