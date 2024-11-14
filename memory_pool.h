#pragma once

#include <vector>
#include <memory>
#include <stack>

constexpr size_t INITIAL_POOL_SIZE = 1000;
constexpr size_t EXPANSION_CHUNK_SIZE = 500;

template <typename T>
class MemoryPool
{
    std::stack<T *> pool;
    std::vector<std::unique_ptr<T[]>> allocations;

public:
    MemoryPool(size_t initial_size = INITIAL_POOL_SIZE)
    {
        expandPool(initial_size);
    }

    T *acquire()
    {
        if (pool.empty())
        {
            expandPool(EXPANSION_CHUNK_SIZE);
        }
        T *obj = pool.top();
        pool.pop();
        return obj;
    }

    void clear()
    {
        pool = std::stack<T *>(); // Clear the pool stack
        allocations.clear();      // Clear the allocation blocks
    }

    void release(T *obj)
    {
        pool.push(obj);
    }

private:
    void expandPool(size_t count)
    {
        auto new_block = std::make_unique<T[]>(count);
        for (size_t i = 0; i < count; ++i)
        {
            pool.push(&new_block[i]);
        }
        allocations.push_back(std::move(new_block));
    }
};
