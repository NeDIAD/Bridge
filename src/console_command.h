#pragma once

class CCommand {
    int count_;
    [[maybe_unused]] int argv0_size_;
    [[maybe_unused]] char argument_string_[512], argument_buffer_[512];
    const char *arguments_[64];
    
    public:
        const char *Arg0() const {
            return count_ > 0 && count_ <= 64 && arguments_[0] ? arguments_[0] : "";
        }
};

static_assert(sizeof(CCommand) == 1288, "CS:GO i386 command arguments ABI");

namespace bridge {
    inline int command_dll_id = -1;
}

class ConCommandBase {
    [[maybe_unused]] ConCommandBase *next_ = nullptr;
    bool registered_ = false;
    const char *name_ = "bridge", *help_ = "Show Bridge version and your connection route.";
    int flags_ = 0;
    
    public:
        virtual ~ConCommandBase() = default;
        virtual bool IsCommand() const { return true; }
        virtual bool IsFlagSet(int flag) const { return (flags_ & flag) != 0; }
        virtual void AddFlags(int flags) { flags_ |= flags; }
        virtual void RemoveFlags(int flags) { flags_ &= ~flags; }
        virtual int GetFlags() const { return flags_; }
        virtual const char *GetName() const { return name_; }
        virtual const char *GetHelpText() const { return help_; }
        virtual bool IsRegistered() const { return registered_; }
        virtual int GetDLLIdentifier() const { return bridge::command_dll_id; }
        
    protected:
        virtual void Create(const char *name, const char *help, int flags) {
            name_ = name;
            help_ = help;
            flags_ = flags;
        }
        virtual void Init() {}
};

static_assert(sizeof(ConCommandBase) == 24, "CS:GO i386 command base ABI");

class BridgeConsoleCommand final : public ConCommandBase {
    using Callback = void (*)(const CCommand &);
    Callback callback_;
    
    [[maybe_unused]] void *completion_ = nullptr;
    [[maybe_unused]] bool has_completion_ : 1;
    [[maybe_unused]] bool new_callback_ : 1;
    [[maybe_unused]] bool callback_interface_ : 1;
    
    public:
        explicit BridgeConsoleCommand(Callback callback)
        : callback_(callback), has_completion_(false), new_callback_(true),
          callback_interface_(false) {}
          
        virtual int AutoCompleteSuggest(const char *, void *) { return 0; }
        virtual bool CanAutoComplete() { return false; }
        virtual void Dispatch(const CCommand &command) { callback_(command); }
};

static_assert(sizeof(BridgeConsoleCommand) == 36, "CS:GO i386 console command ABI");