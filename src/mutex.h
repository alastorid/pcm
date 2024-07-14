#ifndef MUTEX_HEADER_
#define MUTEX_HEADER_

#ifdef _MSC_VER
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <stdlib.h>

namespace pcm
{
    class Mutex {
        Mutex(const Mutex&) = delete;
        Mutex& operator = (const Mutex&) = delete;
#ifdef _MSC_VER
        // mutex on Windows is slow af
        CRITICAL_SECTION cs_;
#else
        pthread_mutex_t mutex_;
#endif

    public:
        Mutex()
        {
#ifdef _MSC_VER
            InitializeCriticalSection(&cs_);
#else
            pthread_mutex_init(&mutex_, NULL);
#endif
        }
        virtual ~Mutex()
        {
#ifdef _MSC_VER
            DeleteCriticalSection(&cs_);
#else
            if (pthread_mutex_destroy(&mutex_) != 0) std::cerr << "pthread_mutex_destroy failed\n";
#endif
        }

        void lock()
        {
#ifdef _MSC_VER
            EnterCriticalSection(&cs_);
#else
            if (pthread_mutex_lock(&mutex_) != 0) std::cerr << "pthread_mutex_lock failed\n";;
#endif
        }
        void unlock()
        {
#ifdef _MSC_VER
            LeaveCriticalSection(&cs_);
#else
            if(pthread_mutex_unlock(&mutex_) != 0) std::cerr << "pthread_mutex_unlock failed\n";
#endif
        }

        class Scope {
            Mutex & m;
            Scope() = delete;
            Scope(const Scope &) = delete;
            Scope & operator = (const Scope &) = delete;
        public:
            Scope(Mutex & m_) : m(m_)
            {
                m.lock();
            }
            ~Scope() {
                m.unlock();
            }
        };
    };
}

#endif
