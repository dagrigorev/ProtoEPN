#pragma once
#include <string>
#include <variant>
#include <stdexcept>
#include <utility>

namespace epn::core {

// ─── Sentinel tag so Result<std::string> doesn't collide ─────────────────────
struct ErrTag { std::string msg; };

template<typename T>
class Result {
public:
    static Result ok(T v)             { Result r; r.data_ = std::move(v);       return r; }
    static Result err(std::string m)  { Result r; r.data_ = ErrTag{std::move(m)}; return r; }

    [[nodiscard]] bool is_ok()  const noexcept { return std::holds_alternative<T>(data_); }
    [[nodiscard]] bool is_err() const noexcept { return !is_ok(); }

    [[nodiscard]] T& value() & {
        if (is_err()) throw std::runtime_error("Result::value() on error: " + std::get<ErrTag>(data_).msg);
        return std::get<T>(data_);
    }
    [[nodiscard]] const T& value() const& {
        if (is_err()) throw std::runtime_error("Result::value() on error: " + std::get<ErrTag>(data_).msg);
        return std::get<T>(data_);
    }
    [[nodiscard]] T value() && {
        if (is_err()) throw std::runtime_error("Result::value() on error: " + std::get<ErrTag>(data_).msg);
        return std::get<T>(std::move(data_));
    }
    [[nodiscard]] const std::string& error() const {
        if (is_ok()) throw std::runtime_error("Result::error() on ok value");
        return std::get<ErrTag>(data_).msg;
    }

    T value_or(T def) const { return is_ok() ? std::get<T>(data_) : std::move(def); }
    explicit operator bool() const noexcept { return is_ok(); }

    template<typename F>
    auto map(F&& f) -> Result<std::invoke_result_t<F, T>> {
        using U = std::invoke_result_t<F, T>;
        if (is_ok()) return Result<U>::ok(f(std::get<T>(data_)));
        return Result<U>::err(std::get<ErrTag>(data_).msg);
    }

private:
    std::variant<T, ErrTag> data_{ErrTag{"uninit"}};
};

// ─── void specialisation ─────────────────────────────────────────────────────
template<>
class Result<void> {
public:
    static Result ok()              { Result r; r.ok_ = true;              return r; }
    static Result err(std::string m){ Result r; r.ok_ = false; r.err_ = std::move(m); return r; }

    [[nodiscard]] bool is_ok()  const noexcept { return ok_; }
    [[nodiscard]] bool is_err() const noexcept { return !ok_; }
    [[nodiscard]] const std::string& error() const { return err_; }
    explicit operator bool() const noexcept { return ok_; }

private:
    bool        ok_{false};
    std::string err_;
};

using VoidResult = Result<void>;

} // namespace epn::core
