#include <cstddef>  // for std::size_t
#include <iterator> // for std::begin and std::end

template <typename T>
class Span
{
public:
    // Default constructor for an empty Span
    Span() : data_(nullptr), size_(0) {}
    // Constructors
    Span(const T *ptr, std::size_t size) : data_(ptr), size_(size) {}

    template <std::size_t N>
    Span(const T (&array)[N]) : data_(array), size_(N) {}

    template <typename Container>
    Span(const Container &container) : data_(container.data()), size_(container.size()) {}

    // Accessors
    const T *data() const { return data_; }
    std::size_t size() const { return size_; }

    // Check if the span is empty
    bool empty() const { return size_ == 0; }

    // Element access
    const T &operator[](std::size_t index) const { return data_[index]; }

    // Iterators for range-based for loop support
    const T *begin() const { return data_; }
    const T *end() const { return data_ + size_; }

private:
    const T *data_;
    std::size_t size_;
};