import React, { useState, useEffect, useRef } from 'react';
import { LANGUAGES } from '../utils/presets';
import { Icons } from './Icons';
import { Avatar, AvatarFallback } from './ui/avatar';
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from './ui/dropdown-menu';
import { Button } from './ui/button';
import { Languages } from 'lucide-react';
import axios from "axios";

interface TranslationProps {
  messageId: string;
  textElement: string | string[];
  toLanguage: string;
  setToLanguage: (value: string) => void;
}

export const Translation: React.FC<TranslationProps> = (props: TranslationProps) => {
  const { messageId, textElement, toLanguage, setToLanguage } = props;
  const [translation, setTranslation] = useState<string | null>(null);
  const [translating, setTranslating] = useState<boolean | null>(null);
  const [showTranslation, setShowTranslation] = useState(false); // State to control translation display
  const [translatedText, setTranslatedText] = useState<string | null>(null);

  const fetchTranslation = async () => {
    console.log("fetch");
    const response = await axios.post('/api/translate', {
      text: textElement,
      lang: toLanguage,
    }, {
      headers: { "Content-Type": "application/json" }
    });
    setTranslatedText(response.data.translationResponse.translation_text);  
    
    setShowTranslation(true); // Show the translation
    // console.log("respone :", translation);
  };

  function generateTranslation() {
    if (translating || toLanguage === 'Select language') {
      return;
    }

    setTranslating(true);
    // console.log('transilation language :', toLanguage);
    fetchTranslation();
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        asChild
        className='overflow-visible'
      >
        <Button className='rounded-full h-4 w-6 aspect-square bg-transparent'>
          <Avatar className='relative w-6 h-4 bg-transparent'>
            <AvatarFallback>
              <Languages className='h-4 w-4 bg-slate-600' />
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent className='bg-white' align='end'>
        <div className='flex items-center justify-start gap-2 p-2'>
          <div className='flex flex-col space-y-0.5 leading-none'>
            {!translating && (
              <div className='flex flex-col gap-1 mb-4'>
                <p className='text-xs sm:text-sm font-medium text-slate-500 mr-auto'>To language</p>
                <div className='flex items-stretch gap-2 sm:gap-4'>
                  <select value={toLanguage} className='flex-1 outline-none w-full focus:outline-none bg-white duration-200 p-2 rounded' onChange={(e) => setToLanguage(e.target.value)}>
                    <option value={'Select language'}>Select language</option>
                    {Object.entries(LANGUAGES).map(([key, value]) => (
                      <option key={key} value={value}>{key}</option>
                    ))}
                  </select>
                  <button onClick={generateTranslation} className='specialBtn px-3 py-2 rounded-lg text-blue-400 hover:text-blue-600 duration-200'>Translate</button>
                </div>
              </div>
            )}
            {showTranslation && (
  <div className='mt-4'>
    <p className='text-base font-medium text-slate-700'>Translated Text:</p>
    <div
      className='p-2 rounded-lg bg-gray-100 text-sm overflow-x-auto'
      style={{ maxWidth: '480px' }} 
    >
      {translatedText}
    </div>
  </div>
)}
          </div>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default Translation;
