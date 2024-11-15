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
    std::vector<size_t> allocationSizes;      // Track sizes of allocations
    std::unordered_map<K, T *> cache;         // Cache for frequently used instances keyed by K
    std::unordered_map<T *, K> reverse_cache; // Reverse lookup to find key by object pointer

public:
    MemoryPool(size_t initial_size = INITIAL_POOL_SIZE)
    {
        cache.reserve(initial_size);
        reverse_cache.reserve(initial_size);
        allocations.reserve(initial_size / EXPANSION_CHUNK_SIZE + 1); // Estimate allocations
        expandPool(initial_size);
    }

    inline T *acquire()
    {
        if (pool.size() > 1)
        {
            __builtin_prefetch(pool.top()); // Prefetch the next object in the pool
        }
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
            __builtin_prefetch(it->second); // Prefetch the cached object
            return it->second;              // If already in cache, return cached instance
        }
        T *instance = acquire();       // Otherwise, acquire new instance
        it->second = instance;         // Update cache entry
        reverse_cache[instance] = key; // Track reverse mapping
        return instance;
    }

    T **batchAcquire(size_t count, const std::vector<K> &keys = {})
    {
        T **array = new T *[count]; // Dynamically allocate memory for the array

        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count && !pool.empty())
            {
                __builtin_prefetch(pool.top()); // Prefetch the next object in the pool
            }

            if (!keys.empty() && i < keys.size())
            {
                // Use acquireWithKey if a key is provided
                array[i] = acquireWithKey(keys[i]);
            }
            else
            {
                // Regular acquire for elements without keys
                array[i] = acquire();
            }
        }

        return array; // Return the dynamically allocated array
    }

    T *acquireBlock(size_t count)
    {
        auto block = std::make_unique<T[]>(count);
        T *blockPtr = block.get();
        allocations.push_back(std::move(block)); // Keep the block in allocations to manage its lifetime
        return blockPtr;
    }

    T **batchAcquireContiguous(size_t count, const std::vector<K> &keys = {})
    {
        thread_local std::vector<T *> temp_array;
        temp_array.resize(count);

        T *block = acquireBlock(count);

        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count)
            {
                __builtin_prefetch(pool.top()); // Prefetch the next object in the pool
            }

            if (!keys.empty() && i < keys.size())
            {
                // Cache each contiguous block element with a key
                temp_array[i] = acquireWithKey(keys[i]);
            }
            else
            {
                temp_array[i] = &block[i];
            }
        }

        return temp_array.data();
    }

    inline void release(T *obj)
    {
        if (reverse_cache.erase(obj))
        {
            // If found and erased from reverse_cache, skip adding to pool
            return;
        }
        pool.push(obj); // Return the object to the pool
        releaseCount++;
        if (releaseCount % 100 == 0)
        {
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
            if (i + 1 < count)
            {
                __builtin_prefetch(array[i + 1]); // Prefetch the next object to release
            }
            auto reverse_it = reverse_cache.find(array[i]);
            if (reverse_it == reverse_cache.end())
            {
                pool.push(array[i]); // Only return to pool if not in cache
            }
        }
        delete[] array; // Safe deletion of dynamically allocated array
    }

    void shrinkToFit()
    {
        while (!allocations.empty() && pool.size() <= allocationSizes.back())
        {
            allocations.pop_back();     // Remove the block from allocations
            allocationSizes.pop_back(); // Remove the corresponding size
        }
    }

    void clear()
    {
        pool = std::stack<T *>();
        cache.clear();
        reverse_cache.clear();
        shrinkToFit(); // Free unused blocks
    }

    size_t poolSize() const { return pool.size(); }
    size_t cacheSize() const { return cache.size(); }
    size_t reverseCacheSize() const { return reverse_cache.size(); }
    size_t allocationCount() const { return allocations.size(); }

private:
    size_t releaseCount = 0;
    size_t lastShrinkReleaseCount = 0;

    inline void expandPool(size_t count)
    {
        auto new_block = std::make_unique<T[]>(count);
        T *block_ptr = new_block.get();
        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count)
            {
                __builtin_prefetch(&block_ptr[i + 1]); // Prefetch the next object in the block
            }
            pool.push(block_ptr + i); // Push pointers sequentially
        }
        allocations.push_back(std::move(new_block));
        allocationSizes.push_back(count);
    }
};