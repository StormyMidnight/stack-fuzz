CXX ?= g++
AFLXX ?= afl-clang-fast++
STD = -std=c++17
INC = -Iinclude
BUILD = build
# -fno-sanitize-recover=all is required: by default ASan/UBSan print a
# report and KEEP RUNNING, which means the process exits 0 and AFL++
# never sees a crash. This flag makes any sanitizer report abort the
# process immediately, which is what turns UB into an actual AFL crash.
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=all

.PHONY: all plain afl afl-asan asan tools clean

all: plain

COMMON_HDRS = include/stack_op_factory.hpp

# --- Plain builds: sanity-check that everything compiles/runs normally ---
plain: $(BUILD)/mystack_plain $(BUILD)/stlstack_plain $(BUILD)/mystack_buggy_plain

$(BUILD)/mystack_plain: harness/mystack_fuzz.cpp include/mystack.hpp $(COMMON_HDRS)
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/mystack_buggy_plain: harness/mystack_fuzz.cpp include/mystack.hpp $(COMMON_HDRS)
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -DINJECT_BUG -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/stlstack_plain: harness/stlstack_fuzz.cpp include/stl_stack_wrapper.hpp $(COMMON_HDRS)
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -O1 -o $@ harness/stlstack_fuzz.cpp

# --- Analysis tool: replays a single AFL testcase and prints the stack
#     states it produces (see tools/stack_trace.cpp and
#     analysis/visualize_stacks.py) ---
tools: $(BUILD)/stack_trace

$(BUILD)/stack_trace: tools/stack_trace.cpp include/mystack.hpp include/stl_stack_wrapper.hpp $(COMMON_HDRS)
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -O1 -o $@ tools/stack_trace.cpp

# --- ASan/UBSan builds (no AFL instrumentation): catches UB even outside AFL ---
asan: $(BUILD)/mystack_asan $(BUILD)/stlstack_asan $(BUILD)/mystack_buggy_asan

$(BUILD)/mystack_asan: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -O1 -g $(SANFLAGS) -o $@ harness/mystack_fuzz.cpp

$(BUILD)/mystack_buggy_asan: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -DINJECT_BUG -O1 -g $(SANFLAGS) -o $@ harness/mystack_fuzz.cpp

$(BUILD)/stlstack_asan: harness/stlstack_fuzz.cpp include/stl_stack_wrapper.hpp
	@mkdir -p $(BUILD)
	$(CXX) $(STD) $(INC) -O1 -g $(SANFLAGS) -o $@ harness/stlstack_fuzz.cpp

# --- AFL++ instrumented builds (requires AFL++ installed: afl-clang-fast++) ---
# Plain AFL instrumentation, no sanitizer. Good for coverage/speed numbers.
afl: $(BUILD)/mystack_afl $(BUILD)/stlstack_afl $(BUILD)/mystack_buggy_afl

$(BUILD)/mystack_afl: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	$(AFLXX) $(STD) $(INC) -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/mystack_buggy_afl: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	$(AFLXX) $(STD) $(INC) -DINJECT_BUG -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/stlstack_afl: harness/stlstack_fuzz.cpp include/stl_stack_wrapper.hpp
	@mkdir -p $(BUILD)
	$(AFLXX) $(STD) $(INC) -O1 -o $@ harness/stlstack_fuzz.cpp

# AFL++ instrumented AND built with ASan, via AFL_USE_ASAN. This is the
# build you actually want to run afl-fuzz against -- without a sanitizer,
# std::stack's UB on empty pop/top may never visibly crash.
afl-asan: $(BUILD)/mystack_afl_asan $(BUILD)/stlstack_afl_asan $(BUILD)/mystack_buggy_afl_asan

$(BUILD)/mystack_afl_asan: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	AFL_USE_ASAN=1 $(AFLXX) $(STD) $(INC) -fsanitize=undefined -fno-sanitize-recover=all -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/mystack_buggy_afl_asan: harness/mystack_fuzz.cpp include/mystack.hpp
	@mkdir -p $(BUILD)
	AFL_USE_ASAN=1 $(AFLXX) $(STD) $(INC) -fsanitize=undefined -fno-sanitize-recover=all -DINJECT_BUG -O1 -o $@ harness/mystack_fuzz.cpp

$(BUILD)/stlstack_afl_asan: harness/stlstack_fuzz.cpp include/stl_stack_wrapper.hpp
	@mkdir -p $(BUILD)
	AFL_USE_ASAN=1 $(AFLXX) $(STD) $(INC) -fsanitize=undefined -fno-sanitize-recover=all -O1 -o $@ harness/stlstack_fuzz.cpp

clean:
	rm -rf $(BUILD)