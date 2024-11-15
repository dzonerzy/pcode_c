#pragma once

#include <vector>
#include <memory>
#include <stack>
#include <unordered_map>

constexpr size_t INITIAL_POOL_SIZE = 1000;
constexpr size_t EXPANSION_CHUNK_SIZE = 500;

template <typename T, typename K>
class MemoryPool
{
    std::stack<T *> pool;
    std::vector<std::unique_ptr<T[]>> allocations;
    std::unordered_map<K, T *> cache;         // Cache for frequently used instances keyed by K
    std::unordered_map<T *, K> reverse_cache; // Reverse lookup to find key by object pointer

public:
    MemoryPool(size_t initial_size = INITIAL_POOL_SIZE)
    {
        cache.reserve(initial_size);         // Reserve space for cache
        reverse_cache.reserve(initial_size); // Reserve space for reverse cache
        expandPool(initial_size);
    }

    inline T *acquire()
    {
        if (pool.empty())
        {
            expandPool(EXPANSION_CHUNK_SIZE);
        }
        T *obj = pool.top();
        pool.pop();
        return obj;
    }

    T *acquireWithKey(const K &key)
    {
        auto [it, inserted] = cache.try_emplace(key, nullptr); // Attempt to emplace
        if (!inserted)
        {
            return it->second; // If already in cache, return cached instance
        }
        T *instance = acquire();       // Otherwise, acquire new instance
        it->second = instance;         // Update cache entry
        reverse_cache[instance] = key; // Track reverse mapping
        return instance;
    }

    T **batchAcquire(size_t count)
    {
        thread_local std::vector<T *> temp_array(512);
        temp_array.resize(count); // Adjust size for the current batch
        for (size_t i = 0; i < count; ++i)
        {
            temp_array[i] = acquire();
        }
        return temp_array.data(); // Return pointer to the internal array
    }

    T *acquireBlock(size_t count)
    {
        auto block = std::make_unique<T[]>(count);
        T *blockPtr = block.get();
        allocations.push_back(std::move(block)); // Keep the block in allocations to manage its lifetime
        return blockPtr;
    }

    T **batchAcquireContiguous(size_t count)
    {
        thread_local std::vector<T *> temp_array(512);
        temp_array.resize(count);
        T *block = acquireBlock(count);
        for (size_t i = 0; i < count; ++i)
        {
            temp_array[i] = &block[i];
        }
        return temp_array.data();
    }

    inline void release(T *obj)
    {
        // Check if the object is in the cache
        auto reverse_it = reverse_cache.find(obj);
        if (reverse_it != reverse_cache.end())
        {
            // If the object is cached, do not release it back to the pool
            return;
        }
        // If not in cache, return the object to the pool
        pool.push(obj);
        releaseCount++;
        if (releaseCount % 100 == 0)
        { // Check every 100 releases
            shrinkToFit();
        }
    }

    void releaseWithKey(const K &key)
    {
        auto it = cache.find(key);
        if (it != cache.end())
        {
            reverse_cache.erase(it->second); // Remove from reverse cache
            pool.push(it->second);           // Return object to the pool
            cache.erase(it);                 // Remove from cache
        }
    }

    void batchRelease(T **array, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            release(array[i]);
        }
        delete[] array;
    }

    void shrinkToFit()
    {
        while (!allocations.empty() && pool.size() <= allocations.back()->size())
        {
            allocations.pop_back(); // Remove unused blocks
        }
    }

    void clear()
    {
        pool = std::stack<T *>();
        cache.clear();
        reverse_cache.clear();
        shrinkToFit(); // Free unused blocks
    }

private:
    size_t releaseCount = 0;

    inline void expandPool(size_t count)
    {
        auto new_block = std::make_unique<T[]>(count);
        T *block_ptr = new_block.get();
        for (size_t i = 0; i < count; ++i)
        {
            pool.push(block_ptr + i); // Push pointers sequentially
        }
        allocations.push_back(std::move(new_block));
    }
};
