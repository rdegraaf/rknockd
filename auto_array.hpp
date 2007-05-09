#ifndef LIBWHEEL_AUTO_ARRAY_HPP
    #define LIBWHEEL_AUTO_ARRAY_HPP

    /* based on Daryle Walker's post to comp.std.c++ on Mar 11, 2005 */
    
    #include <cstddef>      // for size_t

    namespace LibWheel
    {
        template <typename T>
        class auto_array
        {
          private:
            struct auto_array_ref
            {
                T* ptr;
                explicit auto_array_ref(T* p);
            };
            
            T* ptr;
            
          public:
            typedef T element_type;

            explicit auto_array(element_type* p = 0) throw();
            auto_array(auto_array& a) throw() ;

            auto_array<element_type>& operator=(auto_array& a) throw();
            auto_array<element_type>& operator=(auto_array_ref ref) throw();

            ~auto_array() throw();
            
            element_type& operator[] (std::size_t i) const throw();
            element_type* get() const throw();
            element_type* release() throw();
            void reset(element_type* p = 0) throw();
            
            auto_array(auto_array_ref ref) throw();
            operator auto_array_ref() throw();
        };
        

        template <typename T>
        auto_array<T>::auto_array(element_type* p) throw()
        : ptr(p) 
        {}


        template <typename T>
        auto_array<T>::auto_array(auto_array& a) throw() 
        : ptr(a.release()) 
        {}


        template <typename T>
        auto_array<T>&
        auto_array<T>::operator=(auto_array& a) throw()
        {
            reset(a.release());
            return *this;
        }


        template <typename T>
        auto_array<T>&
        auto_array<T>::operator=(auto_array_ref ref) throw()
        {
            reset(ref.ptr);
            return *this;
        }


        template <typename T>
        auto_array<T>::~auto_array() throw()
        {
            delete[] ptr;
        }


        template <typename T>
        T&
        auto_array<T>::operator[] (std::size_t i) const throw()
        {
            return ptr[i];
        }


        template <typename T>
        T*
        auto_array<T>::get() const throw()
        {
            return ptr;
        }


        template <typename T>
        T*
        auto_array<T>::release() throw()
        {
            element_type* tmp = ptr;
            ptr = 0;
            return tmp;
        }


        template <typename T>
        void
        auto_array<T>::reset(element_type* p) throw()
        {
            if (p != ptr)
            {
                delete[] ptr;
                ptr = p;
            }
        }


        template <typename T>
        auto_array<T>::auto_array(auto_array_ref ref) throw()
        : ptr(ref.ptr)
        {}


        template <typename T>
        auto_array<T>::operator auto_array_ref() throw()
        {
            return auto_array_ref(this->release());
        }

        
        template <typename T>
        auto_array<T>::auto_array_ref::auto_array_ref(T* p)
        : ptr(p)
        {}

    } // namespace LibWheel

#endif /* LIBWHEEL_AUTO_ARRAY_HPP */
