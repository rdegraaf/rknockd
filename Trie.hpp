#ifndef LIBWHEEL_TRIE_HPP
    #define LIBWHEEL_TRIE_HPP
    
    #include <vector>
    #include <list>
    #include <string>
    #include <stdexcept>
    #include <tr1/unordered_map>

    // Note: this implementation doesn't allow more than one result at a time

    namespace LibWheel
    {

        class UninitializedException : public std::runtime_error
        {
          public:
            UninitializedException(const std::string& s);
        };

        template <typename CharType, typename MatchType>
        class Trie
        {
            struct Node
            {
                typedef std::tr1::unordered_map<CharType, Node*> TransitionsType;
                const MatchType* match;
                TransitionsType transitions;
                Node();
                friend class Trie;
            };
          public:
            typedef std::vector<CharType> StringType;
            Trie();
            virtual ~Trie();
            virtual void addString(const StringType& str, const MatchType& match);
            virtual const MatchType* search(const StringType& str) const;
            virtual const MatchType* search(const CharType* str, size_t strlen) const;

          protected:
            std::list<Node> tree;
        };

    } // namespace LibWheel

#include "Trie_impl.cpp"

#endif /* LIBWHEEL_TRIE_HPP */
