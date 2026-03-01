#pragma once
#include <map>
#include <variant>
#include <array>
#include <vector>
#include <string>
#include <mutex>
#include <memory>

struct keybind_t {
    int key, mode;
};

struct checkbox_t
{
    std::string name;
    bool enabled;
    keybind_t keybind;
};

struct slider_t
{
    std::string name;
    float callback, vmin, vmax;
    std::string format = "%.1f";
};

struct dropdown_t
{
    std::string name;
    int callback;
    std::vector<std::string> variants;
};

enum config_type
{
    checkbox_type,
    slider_type,
    dropdown_type
};

using config_variant = std::variant<checkbox_t, slider_t, dropdown_t>;

class c_config
{
public:

    void init_config();
    void Save(const std::string& path);
    void Load(const std::string& path);

    template <typename T>
    T& get(const std::string& name) { 
        auto it = options.find(name);
        if (it != options.end()) {
            if (T* val = std::get_if<T>(&it->second))
                return *val;
        }
        static T dummy{};
        return dummy;
    }

    template <typename T>
    T* fill(const std::string& name)
    {
        auto it = options.find(name);
        if (it != options.end()) {
            return std::get_if<T>(&it->second);
        }
        return nullptr;
    }

    std::vector<std::pair<std::string, int>> order;

private:

    template <typename T, typename... Args>
    void add_option(const std::string& name, Args&&... args)
    {
        T option{ name, std::forward<Args>(args)... };
        options[name] = option;
        order.push_back({ name, get_type<T>() });
    }

    template <typename T>
    int get_type() const
    {
        if constexpr (std::is_same_v<T, checkbox_t>) return checkbox_type;
        if constexpr (std::is_same_v<T, slider_t>) return slider_type;
        if constexpr (std::is_same_v<T, dropdown_t>) return dropdown_type;
    }

    std::map<std::string, config_variant> options;
};

inline std::unique_ptr<c_config> cfg = std::make_unique<c_config>();